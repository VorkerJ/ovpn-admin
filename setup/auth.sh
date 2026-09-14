#!/usr/bin/env sh
# OpenVPN auth-user-pass-verify script (via-file mode).
#
# Per-user optional password on top of the certificate. With
# auth-user-pass-optional in server.conf, cert-only users connect without a
# password prompt; only users that have a password entry in users.db must
# present a valid one.
#
# Identity is the CERTIFICATE CN ($common_name), never the typed username — so a
# client cannot present someone else's username, and a password-required user
# cannot bypass the check by stripping auth-user-pass from their config (this
# script still runs and enforces based on the cert CN).

PATH=$PATH:/usr/local/bin
set -e

DB=/etc/openvpn/easyrsa/pki/users.db
cn="${common_name}"

# Defensive CN validation (matches the validateUsername regex in ovpn-admin).
case "${cn}" in
  -*)
    echo "auth.sh: CN must not start with '-'" >&2
    exit 1
    ;;
esac
if ! printf '%s' "${cn}" | grep -Eq '^[A-Za-z0-9_@][A-Za-z0-9_.@-]*$'; then
  echo "auth.sh: invalid CN format" >&2
  exit 1
fi

# Does this certificate's user require a password? has-password uses a
# TRI-STATE exit code so a broken users.db fails CLOSED (audit F02):
#   0 = password required, 1 = cert-only (allow), 2 = error / revoked / deleted.
# We must read the exit code WITHOUT `set -e` aborting on a non-zero result.
set +e
openvpn-user has-password --db.path "${DB}" --user "${cn}" 2>/dev/null
rc=$?
set -e

case "${rc}" in
  0)
    # Password-required: the provided password must verify against the CN.
    # $1 is the via-file: line 1 = username (ignored — we key on the cert CN),
    # line 2 = password. openvpn-user exits non-zero on mismatch; set -e denies.
    auth_passwd=$(tail -1 "$1")
    openvpn-user auth --db.path "${DB}" --user "${cn}" --password "${auth_passwd}"
    ;;
  1)
    # Cert-only user — certificate already verified by OpenVPN. Allow.
    exit 0
    ;;
  *)
    # Unknown/error status (DB failure, revoked/deleted) — DENY, never fall
    # through to a certificate-only allow.
    echo "auth.sh: has-password returned status ${rc} for CN ${cn} — denying" >&2
    exit 1
    ;;
esac
