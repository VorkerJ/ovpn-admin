#!/usr/bin/env sh

PATH=$PATH:/usr/local/bin
set -e

auth_usr=$(head -1 "$1")
auth_passwd=$(tail -1 "$1")

# Reject usernames that could be parsed as a flag by openvpn-user CLI, or
# that contain characters outside the conservative server-side allowlist
# (matches the validateUsername regex enforced by ovpn-admin on creation).
case "${auth_usr}" in
  -*)
    echo "auth.sh: username must not start with '-'" >&2
    exit 1
    ;;
esac
if ! printf '%s' "${auth_usr}" | grep -Eq '^[A-Za-z0-9_@][A-Za-z0-9_.@-]*$'; then
  echo "auth.sh: invalid username format" >&2
  exit 1
fi

if [ "$common_name" = "$auth_usr" ]; then
  openvpn-user auth --db.path /etc/openvpn/easyrsa/pki/users.db --user "${auth_usr}" --password "${auth_passwd}"
else
  echo "Authorization failed"
  exit 1
fi
