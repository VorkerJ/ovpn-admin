// Package ovpnuser is a native, dependency-light reimplementation of the
// openvpn-user CLI (https://github.com/pashcovich/openvpn-user, Apache-2.0).
//
// It manages the SQLite password database OpenVPN uses for username/password
// auth (the `auth-user-pass-verify` path). It is wire-compatible with the
// upstream tool: identical table schema, identical stdout messages and exit
// codes, so it is a drop-in replacement for an existing users.db — and removes
// the build-time download of a third-party prebuilt binary.
//
// The same code is invoked two ways:
//   - the ovpn-admin binary dispatches here when argv[0] is "openvpn-user"
//     (via a symlink), so the admin image ships a single binary;
//   - cmd/openvpn-user builds a tiny standalone binary for the OpenVPN server
//     image, built from this same source.
package ovpnuser

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/alecthomas/kingpin.v2"
	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo); driver name "sqlite"
)

// BinName is the command name this CLI answers to (the symlink target).
const BinName = "openvpn-user"

// bcryptCost — upstream used bcrypt.MinCost (4), which is far too weak. Verify
// works against any cost embedded in the stored hash, so existing MinCost
// hashes keep authenticating while new ones are written at a sane strength.
const bcryptCost = bcrypt.DefaultCost

// Error texts mirror upstream so anything matching them keeps working.
var (
	errUserAlreadyExist       = errors.New("user already exist")
	errUserDeleted            = errors.New("user marked as deleted")
	errUserRestore            = errors.New("failed to restore user")
	errUserRevoke             = errors.New("failed to revoke user")
	errUserDelete             = errors.New("failed to delete user")
	errUserIsNotActive        = errors.New("user is not active")
	errPasswordMismatched     = errors.New("password mismatched")
	errTokenMismatched        = errors.New("token mismatched")
	errUserSecretDoesNotExist = errors.New("user secret does not exist")
)

type store struct{ db *sql.DB }

// RunCLI parses args, executes the matching subcommand and returns the process
// exit code (0 = success; non-zero = failure — OpenVPN treats a non-zero exit
// of the `auth` command as "deny").
func RunCLI(args []string) int {
	app := kingpin.New(BinName, "Manage OpenVPN password-auth users (native SQLite, Apache-2.0).")
	app.Terminate(nil) // don't os.Exit from inside; we return the code

	dbPath := app.Flag("db.path", "path to openvpn-user db").Default("./openvpn-user.db").String()

	cInit := app.Command("db-init", "Init db.")
	cMigrate := app.Command("db-migrate", "Migrate db.")

	cCreate := app.Command("create", "Create user.")
	createUser := cCreate.Flag("user", "Username.").Required().String()
	createPass := cCreate.Flag("password", "Password.").Required().String()

	cDelete := app.Command("delete", "Delete user.")
	deleteForce := cDelete.Flag("force", "delete from db.").Short('f').Default("false").Bool()
	deleteUser := cDelete.Flag("user", "Username.").Short('u').Required().String()

	cRevoke := app.Command("revoke", "Revoke user.")
	revokeUser := cRevoke.Flag("user", "Username.").Short('u').Required().String()

	cRestore := app.Command("restore", "Restore user.")
	restoreUser := cRestore.Flag("user", "Username.").Short('u').Required().String()

	cCheck := app.Command("check", "check user existent.")
	checkUser := cCheck.Flag("user", "Username.").Short('u').Required().String()

	cList := app.Command("list", "List active users.")
	listAll := cList.Flag("all", "Show all users include revoked and deleted.").Short('a').Default("false").Bool()

	cAuth := app.Command("auth", "Auth user.")
	authUser := cAuth.Flag("user", "Username.").Short('u').Required().String()
	authPass := cAuth.Flag("password", "Password.").Short('p').String()
	authTotp := cAuth.Flag("totp", "TOTP code.").Short('t').String()

	cChange := app.Command("change-password", "Change password")
	changeUser := cChange.Flag("user", "Username.").Short('u').Required().String()
	changePass := cChange.Flag("password", "Password.").Short('p').Required().String()

	cUpdSecret := app.Command("update-secret", "update OTP secret")
	updSecretUser := cUpdSecret.Flag("user", "Username.").Short('u').Required().String()
	updSecretVal := cUpdSecret.Flag("secret", "Secret.").Short('s').Default("generate").String()

	cGetSecret := app.Command("get-secret", "get OTP secret")
	getSecretUser := cGetSecret.Flag("user", "Username.").Short('u').Required().String()

	cRegApp := app.Command("register-app", "register 2FA application")
	regAppUser := cRegApp.Flag("user", "Username.").Short('u').Required().String()
	regAppTotp := cRegApp.Flag("totp", "TOTP.").Short('t').Required().String()

	cResetApp := app.Command("reset-app", "reset 2FA application")
	resetAppUser := cResetApp.Flag("user", "Username.").Short('u').Required().String()

	cCheckApp := app.Command("check-app", "check 2FA application")
	checkAppUser := cCheckApp.Flag("user", "Username.").Short('u').Required().String()

	parsed, err := app.Parse(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: error: %v\n", BinName, err)
		return 1
	}

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: error: %v\n", BinName, err)
		return 1
	}
	defer func() { _ = db.Close() }()
	s := &store{db: db}

	switch parsed {
	case cInit.FullCommand():
		return s.initDB()
	case cMigrate.FullCommand():
		return s.migrateDB()
	case cCreate.FullCommand():
		return wrap(s.createUser(*createUser, *createPass))
	case cDelete.FullCommand():
		return wrap(s.deleteUser(*deleteUser, *deleteForce))
	case cRevoke.FullCommand():
		return wrap(s.revokeUser(*revokeUser))
	case cRestore.FullCommand():
		return wrap(s.restoreUser(*restoreUser))
	case cCheck.FullCommand():
		_ = s.userExists(*checkUser) // upstream prints nothing here
		return 0
	case cList.FullCommand():
		s.printUsers(*listAll)
		return 0
	case cAuth.FullCommand():
		return s.authCmd(*authUser, *authPass, *authTotp)
	case cChange.FullCommand():
		return wrap(s.changePassword(*changeUser, *changePass))
	case cUpdSecret.FullCommand():
		return wrap(s.updateSecret(*updSecretUser, *updSecretVal))
	case cGetSecret.FullCommand():
		return wrap(s.getSecret(*getSecretUser))
	case cRegApp.FullCommand():
		return wrap(s.registerApp(*regAppUser, *regAppTotp))
	case cResetApp.FullCommand():
		return wrap(s.resetApp(*resetAppUser))
	case cCheckApp.FullCommand():
		ok, err := s.isAppConfigured(*checkAppUser)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: error: %v\n", BinName, err)
			return 1
		}
		if ok {
			fmt.Println("App configured")
		} else {
			fmt.Println("App not configured yet")
		}
		return 0
	}
	return 0
}

// wrap mirrors the upstream behaviour: print the message on success (exit 0),
// print the error to stderr on failure (exit 1).
func wrap(msg string, err error) int {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: error: %v\n", BinName, err)
		return 1
	}
	fmt.Println(msg)
	return 0
}

func (s *store) initDB() int {
	// boolean fields are integer because sqlite has no boolean: 1=true, 0=false
	if _, err := s.db.Exec("CREATE TABLE IF NOT EXISTS users(id integer not null primary key autoincrement, username string UNIQUE, password string, revoked integer default 0, deleted integer default 0)"); err != nil {
		fmt.Fprintf(os.Stderr, "%s: error: %v\n", BinName, err)
		return 1
	}
	if _, err := s.db.Exec("CREATE TABLE IF NOT EXISTS migrations(id integer not null primary key autoincrement, name string)"); err != nil {
		fmt.Fprintf(os.Stderr, "%s: error: %v\n", BinName, err)
		return 1
	}
	fmt.Println("Database initialized")
	return 0
}

func (s *store) migrateDB() int {
	migs := []struct{ name, sql string }{
		{"users_add_secret_column_2022_11_10", "ALTER TABLE users ADD COLUMN secret string"},
		{"users_add_2fa_column_2022_11_11", "ALTER TABLE users ADD COLUMN app_configured integer default 0"},
	}
	for _, m := range migs {
		var c int
		if err := s.db.QueryRow("SELECT count(*) FROM migrations WHERE name = ?", m.name).Scan(&c); err != nil && err != sql.ErrNoRows {
			fmt.Println(err)
		}
		if c == 0 {
			fmt.Printf("Migrating database with new migration %s\n", m.name)
			// Tolerate "duplicate column" if a column already exists from a DB
			// migrated by the upstream tool without a migrations row.
			if _, err := s.db.Exec(m.sql); err != nil {
				fmt.Println(err)
			}
			if _, err := s.db.Exec("INSERT INTO migrations(name) VALUES (?)", m.name); err != nil {
				fmt.Println(err)
			}
		}
	}
	fmt.Println("Migrations are up to date")
	return 0
}

func (s *store) userExists(username string) bool {
	c := 0
	_ = s.db.QueryRow("SELECT count(*) FROM users WHERE username = ?", username).Scan(&c)
	return c == 1
}

func (s *store) userDeleted(username string) bool {
	var deleted int
	_ = s.db.QueryRow("SELECT deleted FROM users WHERE username = ?", username).Scan(&deleted)
	return deleted != 0
}

func (s *store) userIsActive(username string) bool {
	var revoked, deleted int
	if err := s.db.QueryRow("SELECT revoked, deleted FROM users WHERE username = ?", username).Scan(&revoked, &deleted); err != nil {
		return false
	}
	return revoked == 0 && deleted == 0
}

func (s *store) createUser(username, password string) (string, error) {
	if s.userExists(username) {
		return "", errUserAlreadyExist
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	if _, err := s.db.Exec("INSERT INTO users(username, password, secret, revoked, deleted, app_configured) VALUES (?, ?, ?, 0, 0, 0)", username, string(hash), ""); err != nil {
		return "", err
	}
	return "User created", nil
}

func (s *store) deleteUser(username string, force bool) (string, error) {
	q := "UPDATE users SET deleted = 1 WHERE username = ?"
	if force {
		q = "DELETE FROM users WHERE username = ?"
	}
	res, err := s.db.Exec(q, username)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", errUserDelete
	}
	return "User deleted", nil
}

func (s *store) revokeUser(username string) (string, error) {
	if s.userDeleted(username) {
		return "", errUserDeleted
	}
	res, err := s.db.Exec("UPDATE users SET revoked = 1 WHERE username = ?", username)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", errUserRevoke
	}
	return "User revoked", nil
}

func (s *store) restoreUser(username string) (string, error) {
	if s.userDeleted(username) {
		return "", errUserDeleted
	}
	res, err := s.db.Exec("UPDATE users SET revoked = 0 WHERE username = ?", username)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", errUserRestore
	}
	return "User restored", nil
}

func (s *store) changePassword(username, password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	if _, err := s.db.Exec("UPDATE users SET password = ? WHERE username = ?", string(hash), username); err != nil {
		return "", err
	}
	return "Password changed", nil
}

func (s *store) printUsers(all bool) {
	cond := "WHERE deleted = 0 AND revoked = 0"
	if all {
		cond = ""
	}
	rows, err := s.db.Query("SELECT id, username, revoked, deleted, app_configured FROM users " + cond)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = rows.Close() }()
	var lines []string
	for rows.Next() {
		var id, revoked, deleted, appConf int
		var name string
		if err := rows.Scan(&id, &name, &revoked, &deleted, &appConf); err != nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("%d\t %s\t %v\t %v\t %v", id, name, revoked != 0, deleted != 0, appConf != 0))
	}
	if len(lines) == 0 {
		fmt.Println("No users created yet")
		return
	}
	fmt.Println("id\t username\t revoked\t deleted\t app_configured")
	for _, l := range lines {
		fmt.Println(l)
	}
}

func (s *store) authCmd(username, password, totp string) int {
	provided := 0
	if password != "" {
		provided++
	}
	if totp != "" {
		provided++
	}
	if provided != 1 {
		fmt.Println("Please provide only one type of auth flag")
		return 1
	}
	ok, err := s.authUser(username, password, totp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: error: %v\n", BinName, err)
		return 1
	}
	if ok {
		fmt.Println("Authorization successful")
		return 0
	}
	// Defensive: never allow on an ambiguous non-error "false".
	fmt.Println("Authorization failed")
	return 1
}

func (s *store) authUser(username, password, totp string) (bool, error) {
	var pwHash, secret string
	var revoked, deleted, appConf int
	err := s.db.QueryRow(
		"SELECT password, revoked, deleted, secret, app_configured FROM users WHERE username = ?",
		username,
	).Scan(&pwHash, &revoked, &deleted, &secret, &appConf)
	if err != nil {
		return false, err // includes sql.ErrNoRows (no such user)
	}
	if revoked != 0 || deleted != 0 {
		return false, errUserIsNotActive
	}
	switch {
	case password != "" && totp == "":
		if bcrypt.CompareHashAndPassword([]byte(pwHash), []byte(password)) != nil {
			return false, errPasswordMismatched
		}
		return true, nil
	case totp != "" && password == "":
		if len(secret) == 0 {
			return false, errUserSecretDoesNotExist
		}
		if !verifyTOTP(secret, totp) {
			return false, errTokenMismatched
		}
		return true, nil
	default:
		return false, errUserIsNotActive
	}
}

func (s *store) updateSecret(username, secret string) (string, error) {
	if !s.userIsActive(username) {
		return "", errUserIsNotActive
	}
	if secret == "generate" {
		// CSPRNG key bytes, base32-encoded — a TOTP secret must be
		// unpredictable (the previous time-seeded HMAC derivation was not).
		key := make([]byte, 20)
		if _, err := rand.Read(key); err != nil {
			return "", err
		}
		secret = base32.StdEncoding.EncodeToString(key)
	}
	if _, err := s.db.Exec("UPDATE users SET secret = ? WHERE username = ?", secret, username); err != nil {
		return "", err
	}
	return "Secret updated", nil
}

func (s *store) getSecret(username string) (string, error) {
	if !s.userIsActive(username) {
		return "", errUserIsNotActive
	}
	var secret string
	_ = s.db.QueryRow("SELECT secret FROM users WHERE username = ?", username).Scan(&secret)
	return secret, nil
}

func (s *store) isAppConfigured(username string) (bool, error) {
	if !s.userIsActive(username) {
		return false, errUserIsNotActive
	}
	var appConf int
	if err := s.db.QueryRow("SELECT app_configured FROM users WHERE username = ?", username).Scan(&appConf); err != nil {
		return false, err
	}
	return appConf != 0, nil
}

func (s *store) registerApp(username, totp string) (string, error) {
	if !s.userIsActive(username) {
		return "", errUserIsNotActive
	}
	already, err := s.isAppConfigured(username)
	if err != nil {
		return "", err
	}
	if already {
		return "OTP application already configured", nil
	}
	ok, authErr := s.authUser(username, "", totp)
	if authErr != nil {
		return "", authErr
	}
	if ok {
		if _, err := s.db.Exec("UPDATE users SET app_configured = 1 WHERE username = ?", username); err != nil {
			return "", err
		}
		return "OTP application configured", nil
	}
	return "OTP application already configured", nil
}

func (s *store) resetApp(username string) (string, error) {
	if !s.userIsActive(username) {
		return "", errUserIsNotActive
	}
	already, err := s.isAppConfigured(username)
	if err != nil {
		return "", err
	}
	if !already {
		return "OTP application not configured", nil
	}
	if _, err := s.db.Exec("UPDATE users SET app_configured = 0 WHERE username = ?", username); err != nil {
		return "", err
	}
	return "OTP application reset successful", nil
}

// verifyTOTP checks an RFC 6238 TOTP code (SHA-1, 30s step, 6 digits) against a
// base32 secret, with a ±1 window. Used only by the optional VPN-client 2FA
// path (auth --totp / register-app), which this deployment does not exercise.
func verifyTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return false
	}
	counter := time.Now().Unix() / 30
	for _, w := range []int64{0, -1, 1} {
		if totpAt(key, counter+w) == code {
			return true
		}
	}
	return false
}

func totpAt(key []byte, counter int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) | (uint32(sum[off+2]) << 8) | uint32(sum[off+3])
	return fmt.Sprintf("%06d", v%1000000)
}
