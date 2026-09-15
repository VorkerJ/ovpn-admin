package main

import (
	"encoding/json"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// sessionUser extracts the authenticated username from the session cookie.
//
// Callers (the MFA handlers below) are all wrapped in requireAuth, so the
// session has already been validated by middleware before reaching them.
// We still call this to get the username; the returned value cannot be ""
// in practice — if it ever were, requireAuth would have responded 401 first.
func (oAdmin *OvpnAdmin) sessionUser(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	user, ok := verifySession(cookie.Value)
	if !ok {
		return ""
	}
	return user
}

// mfaStatusHandler GET /api/mfa/status — returns whether MFA is enabled for the current user.
//
// Method check is enforced by the requireMethod middleware.
func (oAdmin *OvpnAdmin) mfaStatusHandler(w http.ResponseWriter, r *http.Request) {
	user := oAdmin.sessionUser(r)

	enabled := false
	if oAdmin.mfaStore != nil {
		enabled = oAdmin.mfaStore.isEnabled(user)
	}
	// Audit F46: expose the server's ACTUAL policy so the UI can gate MFA-only
	// actions (e.g. API-token creation) exactly the way the backend does — the
	// button was disabled whenever the user hadn't enrolled, even on servers
	// where MFA is off/optional and the API would have allowed it.
	required := oAdmin.mfaStore != nil && (mfaRequired == nil || *mfaRequired)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":  enabled,
		"required": required,
		// can_manage_tokens mirrors requireAdminMfa's gate (adminHasMfa): true when
		// MFA is satisfied for this session OR not required by the server.
		"can_manage_tokens": oAdmin.adminHasMfa(r),
	})
}

// mfaSetupHandler POST /api/mfa/setup — generates a new TOTP key for the user.
//
// Method check is enforced by the requireMethod middleware.
func (oAdmin *OvpnAdmin) mfaSetupHandler(w http.ResponseWriter, r *http.Request) {
	user := oAdmin.sessionUser(r)

	if oAdmin.mfaStore == nil {
		writeJSONError(w, http.StatusBadRequest, "MFA is not enabled on this server")
		return
	}

	// Prevent rotating an active MFA secret without an explicit disable step —
	// otherwise a hijacked session could swap the secret for the attacker's.
	if existing, ok := oAdmin.mfaStore.get(user); ok && existing.Enabled {
		writeJSONError(w, http.StatusConflict, "MFA already enabled — disable first")
		return
	}

	key, err := generateTOTPKey(user)
	if err != nil {
		log.Errorf("mfaSetup: failed to generate TOTP key for %s: %v", user, err)
		writeJSONError(w, http.StatusInternalServerError, "failed to generate TOTP key")
		return
	}

	if err := oAdmin.mfaStore.set(user, mfaRecord{
		Secret:    key.Secret(),
		Enabled:   false,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		log.Errorf("mfaSetup: failed to persist TOTP secret for %s: %v", user, err)
		writeJSONError(w, http.StatusInternalServerError, "failed to store MFA secret")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"secret": key.Secret(),
		"qr_url": key.URL(),
	})
}

// mfaConfirmHandler POST /api/mfa/confirm — verifies a TOTP code and enables MFA.
//
// Method check is enforced by the requireMethod middleware.
func (oAdmin *OvpnAdmin) mfaConfirmHandler(w http.ResponseWriter, r *http.Request) {
	user := oAdmin.sessionUser(r)

	if oAdmin.mfaStore == nil {
		writeJSONError(w, http.StatusBadRequest, "MFA is not enabled on this server")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request")
		return
	}

	rec, ok := oAdmin.mfaStore.get(user)
	if !ok || rec.Secret == "" {
		writeJSONError(w, http.StatusBadRequest, "MFA setup not started, call POST /api/mfa/setup first")
		return
	}

	if !verifyTOTPCode(rec.Secret, req.Code) {
		writeJSONError(w, http.StatusUnauthorized, "Неверный код подтверждения")
		return
	}

	plainCodes, hashedCodes := generateBackupCodes(8)

	rec.Enabled = true
	rec.BackupCodes = hashedCodes

	// Audit N10: bump the session epoch BEFORE persisting the enable. The old
	// order (set() then bumpUserEpoch()) meant an epoch-bump failure AFTER a
	// successful set() left MFA durably ENABLED while the 500 response withheld the
	// backup codes — the admin ended up with a second factor enrolled but no
	// recovery codes. Bumping first means a failure here (or of set() below) leaves
	// MFA still DISABLED, which is fully recoverable: the admin re-logs in and
	// retries enrollment, getting a fresh set of codes.
	if err := bumpUserEpoch(user); err != nil {
		log.Errorf("mfaConfirm: session epoch bump not persisted for %s: %v", user, err)
		writeJSONError(w, http.StatusInternalServerError, "failed to finalize MFA enable")
		return
	}

	// Commit-then-respond: only hand out backup codes and a 200 once the enable
	// is durably persisted. set() rolls back the in-memory record on failure, so
	// a lost write leaves MFA disabled (not half-enabled) and the user retries.
	if err := oAdmin.mfaStore.set(user, rec); err != nil {
		log.Errorf("mfaConfirm: failed to persist MFA enable for %s: %v", user, err)
		writeJSONError(w, http.StatusInternalServerError, "failed to enable MFA")
		return
	}

	// Audit F23: the epoch bump above invalidated the enrolling session's cookie.
	// The admin just proved the second factor (verifyTOTPCode passed), so issue a
	// FRESH MFA-satisfied session now — otherwise the browser's next authenticated
	// request 401s, the 401 interceptor logs the user out, and the modal showing
	// the one-time backup codes unmounts before they can save them.
	token := signSession(user, true)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   !*insecureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})

	log.Infof("MFA: user %s confirmed TOTP setup", user)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"backup_codes": plainCodes,
	})
}

// mfaDisableHandler DELETE /api/mfa — disables MFA for the current user.
//
// Method check is enforced by the requireMethod middleware.
func (oAdmin *OvpnAdmin) mfaDisableHandler(w http.ResponseWriter, r *http.Request) {
	user := oAdmin.sessionUser(r)

	if oAdmin.mfaStore == nil {
		writeJSONError(w, http.StatusBadRequest, "MFA is not enabled on this server")
		return
	}

	// Rate-limit by client IP and username — disabling MFA is a high-value
	// target for an attacker who has already hijacked a session cookie.
	ip := clientIP(r)
	if !checkLoginRateLimit(ip, user) {
		writeJSONError(w, http.StatusTooManyRequests, "too many attempts")
		return
	}

	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request")
		return
	}

	// Re-authenticate with the current password before tearing down MFA.
	if !validateCredentials(user, req.Password) {
		recordLoginFailure(ip, user)
		writeJSONError(w, http.StatusUnauthorized, "Неверный пароль")
		return
	}

	rec, ok := oAdmin.mfaStore.get(user)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "MFA is not configured for this user")
		return
	}

	// Accept TOTP code or backup code
	codeValid := verifyTOTPCode(rec.Secret, req.Code) || verifyBackupCode(req.Code, rec.BackupCodes)
	if !codeValid {
		recordLoginFailure(ip, user)
		writeJSONError(w, http.StatusUnauthorized, "Неверный код")
		return
	}

	if err := oAdmin.mfaStore.delete(user); err != nil {
		log.Errorf("mfaDisable: failed to persist MFA removal for %s: %v", user, err)
		writeJSONError(w, http.StatusInternalServerError, "failed to disable MFA")
		return
	}
	log.Infof("MFA: user %s disabled TOTP", user)

	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

// mfaLoginHandler POST /api/login/mfa — second step of two-factor login.
//
// Method check is enforced by the requireMethod middleware.
func (oAdmin *OvpnAdmin) mfaLoginHandler(w http.ResponseWriter, r *http.Request) {
	// Reject early if MFA is not configured server-side. Done BEFORE any state
	// mutation (rate-limit counters, jti consumption) so a probe against a
	// non-MFA server cannot poison either.
	if oAdmin.mfaStore == nil {
		writeJSONError(w, http.StatusUnauthorized, "MFA is not enabled on this server")
		return
	}

	ip := clientIP(r)
	if !checkLoginRateLimit(ip) {
		writeJSONError(w, http.StatusTooManyRequests, "too many login attempts, try again later")
		return
	}

	var req struct {
		MfaToken string `json:"mfa_token"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request")
		return
	}

	user, jti, exp, ok := verifyMfaToken(req.MfaToken)
	if !ok {
		recordLoginFailure(ip)
		writeJSONError(w, http.StatusUnauthorized, "invalid or expired MFA token")
		return
	}

	// Now that we know the username, apply the per-user rate limit too.
	if !checkLoginRateLimit(ip, user) {
		writeJSONError(w, http.StatusTooManyRequests, "too many login attempts, try again later")
		return
	}

	// Atomic verify-and-consume (audit F20): validating the code and recording
	// its consumption happen under one store lock, so two concurrent requests
	// can't both spend the same one-shot backup code, and an accepted TOTP step
	// is marked used immediately (replay across adjacent windows is rejected).
	// A persist failure fails closed — no session is issued and the code stays
	// unspent — so nothing is counted-as-used only in memory.
	//
	// Audit F47: verify the CODE before consuming the intermediate token's jti.
	// A wrong code (typo) must NOT burn the challenge — otherwise the user's
	// immediate correct retry with the same token was rejected as "already used",
	// silently locking them out until they went back to the password step.
	res, err := oAdmin.mfaStore.verifyAndConsume(user, req.Code, time.Now())
	if err != nil {
		log.Errorf("mfaLogin: failed to persist MFA consumption for %s: %v", user, err)
		writeJSONError(w, http.StatusInternalServerError, "failed to record MFA state, please retry")
		return
	}
	switch res {
	case mfaReject:
		recordLoginFailure(ip, user)
		time.Sleep(500 * time.Millisecond)
		writeJSONError(w, http.StatusUnauthorized, "invalid TOTP or backup code")
		return
	case mfaOKBackup:
		log.Infof("MFA: user %s used a backup code", user)
	}

	// Second factor verified — NOW consume the intermediate token so it can't be
	// replayed (single-use). The second factor itself is already spent above, so
	// this is a belt-and-suspenders guard on the token; a failure here means a
	// genuine replay, so refuse to issue a session.
	if !consumeMfaJti(jti, exp) {
		recordLoginFailure(ip, user)
		writeJSONError(w, http.StatusUnauthorized, "MFA token already used")
		return
	}

	recordLoginSuccess(ip, user)

	// mfaSatisfied=true: the second factor was just verified above, so this
	// session is allowed to pass the MFA gate (adminHasMfa).
	token := signSession(user, true)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   !*insecureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":   true,
		"user": user,
	})
}
