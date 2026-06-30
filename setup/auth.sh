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

# Does this certificate's user require a password?
if openvpn-user has-password --db.path "${DB}" --user "${cn}" 2>/dev/null; then
  # Password-required: the provided password must verify against the CN.
  # $1 is the via-file: line 1 = username (ignored — we key on the cert CN),
  # line 2 = password.
  auth_passwd=$(tail -1 "$1")
  openvpn-user auth --db.path "${DB}" --user "${cn}" --password "${auth_passwd}"
  # openvpn-user exits non-zero on mismatch; set -e turns that into a deny.
else
  # Cert-only user — certificate already verified by OpenVPN. Allow.
  exit 0
fi
