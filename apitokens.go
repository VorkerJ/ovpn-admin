package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// tokenScheme prefixes every issued token so it is recognizable and so a leaked
// token can be grepped for in logs/secret scanners.
const tokenScheme = "ovpnadm_"

type ctxKey int

const svcAccountCtxKey ctxKey = iota

// apiToken is a service-account credential for non-interactive API access
// (external integrations that create users / set routes). The plaintext is
// shown to the operator exactly once at creation; only its SHA-256 is stored.
//
// Scope is fixed: a token may only reach user- and route-management endpoints
// (see apiTokenPathAllowed). It bypasses the MFA and forced-password-change
// gates — a service can do neither — but cannot touch server config, MFA, the
// admin password, or token management itself.
type apiToken struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Hint       string `json:"hint"` // e.g. "ovpnadm_AbCd…" for the UI
	Hash       string `json:"hash"` // sha256(plaintext) hex; never sent to the UI
	CreatedAt  string `json:"created_at"`
	CreatedBy  string `json:"created_by"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	// AllowConfigExport, when true, opts this token into the client
	// config/private-key export endpoint (/api/user/config/show, which embeds
	// the client PRIVATE KEY). It is default-DENY: an ordinary automation token
	// can create/manage users and routes but must NOT be able to download every
	// user's private key. Grant it only to tokens that genuinely need to hand out
	// full client configs. See create() for where token issuance would set it.
	AllowConfigExport bool `json:"allow_config_export,omitempty"`
}

type apiTokenStore struct {
	mu     sync.Mutex
	path   string
	tokens map[string]*apiToken // id -> token
}

func newAPITokenStore(path string) *apiTokenStore {
	s := &apiTokenStore{path: path, tokens: map[string]*apiToken{}}
	s.load()
	return s
}

func (s *apiTokenStore) load() {
	if s.path == "" {
		return
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var list []*apiToken
	if err := json.Unmarshal(raw, &list); err != nil {
		log.Warnf("api-tokens: failed to parse %s: %v — starting empty", s.path, err)
		return
	}
	for _, t := range list {
		s.tokens[t.ID] = t
	}
	log.Infof("api-tokens: loaded %d service-account token(s) from %s", len(s.tokens), s.path)
}

// save persists the store; callers must hold s.mu.
func (s *apiTokenStore) save() {
	if s.path == "" {
		return
	}
	list := make([]*apiToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		list = append(list, t)
	}
	raw, _ := json.Marshal(list)
	if err := writeFileAtomicSecret(s.path, raw); err != nil {
		log.Warnf("api-tokens: persist to %s failed: %v", s.path, err)
	}
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// create issues a new token and returns the plaintext (shown once) + metadata.
func (s *apiTokenStore) create(name, by string) (string, *apiToken, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil, errors.New("требуется имя токена")
	}
	secretBuf := make([]byte, 32)
	if _, err := rand.Read(secretBuf); err != nil {
		return "", nil, err
	}
	idBuf := make([]byte, 8)
	if _, err := rand.Read(idBuf); err != nil {
		return "", nil, err
	}
	plaintext := tokenScheme + base64.RawURLEncoding.EncodeToString(secretBuf)
	t := &apiToken{
		ID:        hex.EncodeToString(idBuf),
		Name:      name,
		Hint:      plaintext[:len(tokenScheme)+4] + "…",
		Hash:      sha256hex(plaintext),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		CreatedBy: by,
		// AllowConfigExport is deliberately left false here: config/private-key
		// export is opt-in and off by default. When token issuance grows a way to
		// grant that capability (an API/UI flag on creation), set it on t here.
	}
	s.mu.Lock()
	s.tokens[t.ID] = t
	s.save()
	s.mu.Unlock()
	return plaintext, t, nil
}

// verify returns the token whose hash matches the presented plaintext.
func (s *apiTokenStore) verify(plaintext string) (*apiToken, bool) {
	if !strings.HasPrefix(plaintext, tokenScheme) {
		return nil, false
	}
	h := []byte(sha256hex(plaintext))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(t.Hash), h) == 1 {
			return t, true
		}
	}
	return nil, false
}

// touch records last-use, persisting at most once a minute per token to avoid a
// disk write on every API call.
func (s *apiTokenStore) touch(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.tokens[id]
	if t == nil {
		return
	}
	now := time.Now().UTC()
	if t.LastUsedAt != "" {
		if prev, err := time.Parse(time.RFC3339, t.LastUsedAt); err == nil && now.Sub(prev) < time.Minute {
			t.LastUsedAt = now.Format(time.RFC3339)
			return // in-memory only
		}
	}
	t.LastUsedAt = now.Format(time.RFC3339)
	s.save()
}

func (s *apiTokenStore) list() []apiToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]apiToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		c := *t
		c.Hash = "" // never expose the hash
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

func (s *apiTokenStore) revoke(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tokens[id]; !ok {
		return false
	}
	delete(s.tokens, id)
	s.save()
	return true
}

// ── request helpers ─────────────────────────────────────────────────────────

// bearerToken extracts an API token from Authorization: Bearer <t> or the
// X-API-Token header.
func bearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return strings.TrimSpace(r.Header.Get("X-API-Token"))
}

func withServiceAccount(r *http.Request, name string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), svcAccountCtxKey, name))
}

func serviceAccountName(r *http.Request) string {
	if v, ok := r.Context().Value(svcAccountCtxKey).(string); ok {
		return v
	}
	return ""
}

func isServiceAccount(r *http.Request) bool { return serviceAccountName(r) != "" }

// apiTokenPathAllowed enforces the fixed scope: tokens may only manage VPN
// users and routes (and read traffic). Everything else is session-only.
//
// Matching is anchored to whole path segments (== prefix, or prefix+"/...") so
// a lookalike like /api/user-admin or /api/userspace is NOT mistaken for an
// in-scope /api/user* route.
func apiTokenPathAllowed(path string) bool {
	p := strings.TrimPrefix(path, strings.TrimRight(*listenBaseUrl, "/"))
	for _, seg := range []string{"/api/user", "/api/users", "/api/common-routes", "/api/traffic"} {
		if p == seg || strings.HasPrefix(p, seg+"/") {
			return true
		}
	}
	return false
}

// requireTokenConfigExport gates the client config/private-key export endpoint
// for BEARER-TOKEN (service-account) callers only. It is default-DENY: a service
// account may reach it only if its token has AllowConfigExport set.
//
// Human (session) callers pass through untouched — their access to config export
// is governed by the session + MFA gates, not by this capability. Only automation
// tokens are held here, so an ordinary integration token that can create users
// and routes cannot also download every user's private key.
//
// MUST be wrapped INSIDE auth(...) so requireAuth has already validated the token
// and stamped the service-account identity onto the request context. requireAuth
// records only the token's NAME in the context (it cannot be widened without
// touching auth.go), so we re-resolve the exact token from the presented bearer
// credential to read its capability.
func (oAdmin *OvpnAdmin) requireTokenConfigExport(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isServiceAccount(r) {
			next(w, r) // human/session caller — not subject to the token capability
			return
		}
		if oAdmin.apiTokens == nil {
			writeJSONError(w, http.StatusForbidden, "this API token is not permitted to export client configs")
			return
		}
		at, ok := oAdmin.apiTokens.verify(bearerToken(r))
		if !ok || !at.AllowConfigExport {
			writeJSONError(w, http.StatusForbidden, "this API token is not permitted to export client configs (private keys)")
			return
		}
		next(w, r)
	}
}

// ── management handlers (session + MFA gated; tokens can't reach them) ───────

// apiTokensHandler GET (list) / POST (create) /api/api-tokens.
func (oAdmin *OvpnAdmin) apiTokensHandler(w http.ResponseWriter, r *http.Request) {
	if oAdmin.apiTokens == nil {
		writeJSONError(w, http.StatusBadRequest, "api tokens unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, oAdmin.apiTokens.list())
	case http.MethodPost:
		if !oAdmin.adminHasMfa(r) {
			writeJSONError(w, http.StatusPreconditionFailed, "MFA must be enabled to perform this action")
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		plaintext, t, err := oAdmin.apiTokens.create(req.Name, oAdmin.sessionUser(r))
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Infof("api-tokens: created %q (id %s) by %s", t.Name, t.ID, t.CreatedBy)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"id":         t.ID,
			"name":       t.Name,
			"token":      plaintext, // shown exactly once
			"hint":       t.Hint,
			"created_at": t.CreatedAt,
		})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// apiTokenItemHandler DELETE /api/api-tokens/{id}.
func (oAdmin *OvpnAdmin) apiTokenItemHandler(w http.ResponseWriter, r *http.Request) {
	if oAdmin.apiTokens == nil {
		writeJSONError(w, http.StatusBadRequest, "api tokens unavailable")
		return
	}
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !oAdmin.adminHasMfa(r) {
		writeJSONError(w, http.StatusPreconditionFailed, "MFA must be enabled to perform this action")
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, *listenBaseUrl+"api/api-tokens/"), "/")
	if oAdmin.apiTokens.revoke(id) {
		log.Infof("api-tokens: revoked id %s by %s", id, oAdmin.sessionUser(r))
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
	} else {
		writeJSONError(w, http.StatusNotFound, "token not found")
	}
}
