package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// sessionUser extracts the authenticated username from the session cookie.
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
func (oAdmin *OvpnAdmin) mfaStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := oAdmin.sessionUser(r)
	if user == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"unauthorized"}`)
		return
	}

	enabled := false
	if oAdmin.mfaStore != nil {
		enabled = oAdmin.mfaStore.isEnabled(user)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled": enabled,
	})
}

// mfaSetupHandler POST /api/mfa/setup — generates a new TOTP key for the user.
func (oAdmin *OvpnAdmin) mfaSetupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := oAdmin.sessionUser(r)
	if user == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"unauthorized"}`)
		return
	}

	if oAdmin.mfaStore == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"MFA is not enabled on this server"}`)
		return
	}

	// Prevent rotating an active MFA secret without an explicit disable step —
	// otherwise a hijacked session could swap the secret for the attacker's.
	if existing, ok := oAdmin.mfaStore.get(user); ok && existing.Enabled {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, `{"error":"MFA already enabled — disable first"}`)
		return
	}

	key, err := generateTOTPKey(user)
	if err != nil {
		log.Errorf("mfaSetup: failed to generate TOTP key for %s: %v", user, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"failed to generate TOTP key"}`)
		return
	}

	oAdmin.mfaStore.set(user, mfaRecord{
		Secret:    key.Secret(),
		Enabled:   false,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"secret": key.Secret(),
		"qr_url": key.URL(),
	})
}

// mfaConfirmHandler POST /api/mfa/confirm — verifies a TOTP code and enables MFA.
func (oAdmin *OvpnAdmin) mfaConfirmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := oAdmin.sessionUser(r)
	if user == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"unauthorized"}`)
		return
	}

	if oAdmin.mfaStore == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"MFA is not enabled on this server"}`)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid request"}`)
		return
	}

	rec, ok := oAdmin.mfaStore.get(user)
	if !ok || rec.Secret == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"MFA setup not started, call POST /api/mfa/setup first"}`)
		return
	}

	if !verifyTOTPCode(rec.Secret, req.Code) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid TOTP code"}`)
		return
	}

	plainCodes, hashedCodes := generateBackupCodes(8)

	rec.Enabled = true
	rec.BackupCodes = hashedCodes
	oAdmin.mfaStore.set(user, rec)

	log.Infof("MFA: user %s confirmed TOTP setup", user)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"backup_codes": plainCodes,
	})
}

// mfaDisableHandler DELETE /api/mfa — disables MFA for the current user.
func (oAdmin *OvpnAdmin) mfaDisableHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := oAdmin.sessionUser(r)
	if user == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"unauthorized"}`)
		return
	}

	if oAdmin.mfaStore == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"MFA is not enabled on this server"}`)
		return
	}

	// Rate-limit by client IP and username — disabling MFA is a high-value
	// target for an attacker who has already hijacked a session cookie.
	ip := clientIP(r)
	if !checkLoginRateLimit(ip, user) {
		http.Error(w, `{"error":"too many attempts"}`, http.StatusTooManyRequests)
		return
	}

	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid request"}`)
		return
	}

	// Re-authenticate with the current password before tearing down MFA.
	if !validateCredentials(user, req.Password) {
		recordLoginFailure(ip, user)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid credentials"}`)
		return
	}

	rec, ok := oAdmin.mfaStore.get(user)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"MFA is not configured for this user"}`)
		return
	}

	// Accept TOTP code or backup code
	codeValid := verifyTOTPCode(rec.Secret, req.Code) || verifyBackupCode(req.Code, rec.BackupCodes)
	if !codeValid {
		recordLoginFailure(ip, user)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid code"}`)
		return
	}

	oAdmin.mfaStore.delete(user)
	log.Infof("MFA: user %s disabled TOTP", user)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"ok":true}`)
}

// mfaLoginHandler POST /api/login/mfa — second step of two-factor login.
func (oAdmin *OvpnAdmin) mfaLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := clientIP(r)
	if !checkLoginRateLimit(ip) {
		http.Error(w, `{"error":"too many login attempts, try again later"}`, http.StatusTooManyRequests)
		return
	}

	var req struct {
		MfaToken string `json:"mfa_token"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid request"}`)
		return
	}

	user, jti, ok := verifyMfaToken(req.MfaToken)
	if !ok {
		recordLoginFailure(ip)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid or expired MFA token"}`)
		return
	}

	// Now that we know the username, apply the per-user rate limit too.
	if !checkLoginRateLimit(ip, user) {
		http.Error(w, `{"error":"too many login attempts, try again later"}`, http.StatusTooManyRequests)
		return
	}

	// Single-use: mark the jti as consumed so the same intermediate token
	// cannot be replayed (e.g. after a leaked browser history entry).
	if !consumeMfaJti(jti, time.Now().Add(mfaTokenTTL).Unix()) {
		recordLoginFailure(ip, user)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"MFA token already used"}`)
		return
	}

	if oAdmin.mfaStore == nil {
		recordLoginFailure(ip, user)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"MFA is not enabled on this server"}`)
		return
	}

	rec, exists := oAdmin.mfaStore.get(user)
	if !exists || !rec.Enabled {
		recordLoginFailure(ip, user)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"MFA is not configured for this user"}`)
		return
	}

	// Replay protection: reject any TOTP code we already accepted for this
	// user within the validity window (~90s covers the standard ±1 step
	// tolerance pquerna/otp uses). Backup codes are excluded because they
	// are one-shot via consumeBackupCode already.
	if rec.LastUsedCode != "" && rec.LastUsedCode == req.Code && time.Now().Unix()-rec.LastUsedAt < 90 {
		recordLoginFailure(ip, user)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"code already used"}`)
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid TOTP or backup code"}`)
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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":   true,
		"user": user,
	})
}
