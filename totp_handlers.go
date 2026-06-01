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

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled": enabled,
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

	oAdmin.mfaStore.set(user, mfaRecord{
		Secret:    key.Secret(),
		Enabled:   false,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})

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
		writeJSONError(w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}

	plainCodes, hashedCodes := generateBackupCodes(8)

	rec.Enabled = true
	rec.BackupCodes = hashedCodes
	oAdmin.mfaStore.set(user, rec)

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
		writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
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
		writeJSONError(w, http.StatusUnauthorized, "invalid code")
		return
	}

	oAdmin.mfaStore.delete(user)
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

	// Single-use: mark the jti as consumed so the same intermediate token
	// cannot be replayed (e.g. after a leaked browser history entry). The
	// expiry tracked here MUST come from the token itself — using
	// time.Now()+TTL would keep the entry alive past the token's own
	// validity and prematurely garbage-collect older entries.
	if !consumeMfaJti(jti, exp) {
		recordLoginFailure(ip, user)
		writeJSONError(w, http.StatusUnauthorized, "MFA token already used")
		return
	}

	rec, exists := oAdmin.mfaStore.get(user)
	if !exists || !rec.Enabled {
		recordLoginFailure(ip, user)
		writeJSONError(w, http.StatusUnauthorized, "MFA is not configured for this user")
		return
	}

	// Replay protection: reject any TOTP code we already accepted for this
	// user within the validity window (~90s covers the standard ±1 step
	// tolerance pquerna/otp uses). Backup codes are excluded because they
	// are one-shot via consumeBackupCode already.
	if rec.LastUsedCode != "" && rec.LastUsedCode == req.Code && time.Now().Unix()-rec.LastUsedAt < 90 {
		recordLoginFailure(ip, user)
		writeJSONError(w, http.StatusUnauthorized, "code already used")
		return
	}

	// Try TOTP code first, then backup code
	codeValid := verifyTOTPCode(rec.Secret, req.Code)
	backupUsed := false
	if !codeValid {
		if verifyBackupCode(req.Code, rec.BackupCodes) {
			codeValid = true
			backupUsed = true
		}
	}

	if !codeValid {
		recordLoginFailure(ip, user)
		time.Sleep(500 * time.Millisecond)
		writeJSONError(w, http.StatusUnauthorized, "invalid TOTP or backup code")
		return
	}

	// Persist code usage state. For TOTP, remember the code for replay
	// rejection; for backup codes, consume from the list so they can't be
	// reused.
	if backupUsed {
		rec.BackupCodes = consumeBackupCode(req.Code, rec.BackupCodes)
		log.Infof("MFA: user %s used a backup code (%d remaining)", user, len(rec.BackupCodes))
	} else {
		rec.LastUsedCode = req.Code
		rec.LastUsedAt = time.Now().Unix()
	}
	oAdmin.mfaStore.set(user, rec)

	recordLoginSuccess(ip, user)

	token := signSession(user)
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
