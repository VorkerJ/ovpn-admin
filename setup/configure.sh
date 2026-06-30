#!/usr/bin/env bash
set -e

EASY_RSA_LOC="/etc/openvpn/easyrsa"
SERVER_CERT="${EASY_RSA_LOC}/pki/issued/server.crt"

OVPN_SRV_NET=${OVPN_SERVER_NET:-172.16.100.0}
OVPN_SRV_MASK=${OVPN_SERVER_MASK:-255.255.255.0}


cd $EASY_RSA_LOC

if [ -e "$SERVER_CERT" ]; then
  echo "Found existing certs - reusing"
else
  echo "Generating new certs"
  easyrsa --batch init-pki
  cp -R /usr/share/easy-rsa/* $EASY_RSA_LOC/pki
  echo "ca" | easyrsa build-ca nopass
  easyrsa --batch build-server-full server nopass
  easyrsa gen-dh
  openvpn --genkey --secret ./pki/ta.key
fi
easyrsa gen-crl

# Wait for ovpn-admin to render the dynamic server.conf, then derive the VPN
# subnet from it instead of trusting the env var. The env var is read once at
# container start and never updated when the operator changes the subnet via
# the admin UI; reading server.conf at apply time lets us stay correct across
# restarts even when env and JSON config drift apart.
ensure_masquerade() {
  local conf="/etc/openvpn-dynamic/server.conf"
  if [ ! -f "$conf" ]; then
    return
  fi
  # Format: "server NETWORK NETMASK"
  local line net mask
  line=$(grep -E "^server [0-9]" "$conf" | head -1)
  if [ -z "$line" ]; then
    return
  fi
  net=$(echo "$line" | awk '{print $2}')
  mask=$(echo "$line" | awk '{print $3}')
  if [ -z "$net" ] || [ -z "$mask" ]; then
    return
  fi
  # Strip any prior MASQUERADE rules matching our "-s X ! -d X" shape (so
  # Docker bridge MASQUERADE stays untouched), then install the right one.
  iptables-save -t nat 2>/dev/null | awk '/^-A POSTROUTING.*! -d.*-j MASQUERADE/ {gsub("^-A","-D"); print}' \
    | while read -r rule; do
        # shellcheck disable=SC2086
        iptables -t nat $rule 2>/dev/null || true
      done
  iptables -t nat -A POSTROUTING -s "${net}/${mask}" ! -d "${net}/${mask}" -j MASQUERADE \
    || echo "WARN: iptables MASQUERADE failed (Docker Desktop?). VPN clients won't have internet access."
}

# Fallback for the env-driven path (used before ovpn-admin renders server.conf
# for the first time). Will be replaced by ensure_masquerade below as soon as
# server.conf exists.
iptables -t nat -D POSTROUTING -s ${OVPN_SRV_NET}/${OVPN_SRV_MASK} ! -d ${OVPN_SRV_NET}/${OVPN_SRV_MASK} -j MASQUERADE || true
iptables -t nat -A POSTROUTING -s ${OVPN_SRV_NET}/${OVPN_SRV_MASK} ! -d ${OVPN_SRV_NET}/${OVPN_SRV_MASK} -j MASQUERADE || echo "WARN: iptables MASQUERADE failed (Docker Desktop?). VPN clients won't have internet access."

mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200
fi

# Password auth is now toggled from the ovpn-admin GUI (Server tab), which
# renders the auth-user-pass-verify / auth-user-pass-optional / script-security
# directives into server.conf on demand. We therefore ALWAYS stage the verify
# script and ensure users.db exists, so flipping the toggle works immediately
# without touching env vars or restarting the openvpn container. (OVPN_PASSWD_AUTH
# is no longer consulted.)
mkdir -p /etc/openvpn/scripts/
cp -f /etc/openvpn/setup/auth.sh /etc/openvpn/scripts/auth.sh
chmod +x /etc/openvpn/scripts/auth.sh
openvpn-user db-init --db.path=$EASY_RSA_LOC/pki/users.db && openvpn-user db-migrate --db.path=$EASY_RSA_LOC/pki/users.db

# easyrsa creates pki/.lock-easyrsa-* during build-client-full, revoke,
# gen-crl, etc. It needs WRITE in pki/ itself, not just on existing files.
# ovpn-admin runs as a non-root user inside its container and belongs to
# group 2000 (ovpnshared); 755 leaves that group with r-x and easyrsa
# fails with "Failed to create lock-file (permissions?)" — easy to mistake
# for an SELinux issue.
#
# 2775 = setgid + rwxrwxr-x. The setgid bit makes every NEW file created
# under pki/ inherit group 2000 automatically, so subsequent revokes and
# CRL regenerations don't drift back into "wrong group" territory.
if [ -d $EASY_RSA_LOC/pki ]; then
  chgrp 2000 $EASY_RSA_LOC/pki 2>/dev/null || true
  chmod 2775 $EASY_RSA_LOC/pki
fi
[ -f $EASY_RSA_LOC/pki/crl.pem ] && chmod 644 $EASY_RSA_LOC/pki/crl.pem

# The rendered server.conf references /etc/openvpn/pki — point it at easyrsa's pki
[ ! -e /etc/openvpn/pki ] && ln -s $EASY_RSA_LOC/pki /etc/openvpn/pki

mkdir -p /etc/openvpn/ccd

# server.conf is now rendered by ovpn-admin into /etc/openvpn-dynamic/server.conf
# Allow ovpn-admin (non-root, member of GID 2000) to write here.
# 0770 = root + ovpnshared group only, no world access.
# Try Debian-style first (groupadd), fall back to BusyBox/Alpine (addgroup)
# so the same script works in both base-image variants.
( groupadd -g 2000 ovpnshared || addgroup -g 2000 ovpnshared ) 2>/dev/null || true
chown root:2000 /etc/openvpn-dynamic 2>/dev/null || true
chmod 0770 /etc/openvpn-dynamic 2>/dev/null || true
echo "Waiting for ovpn-admin to render server.conf..."
until [ -f /etc/openvpn-dynamic/server.conf ]; do
  sleep 1
done

# Now that ovpn-admin has rendered server.conf, replace the env-derived
# MASQUERADE with one matching whatever subnet the JSON config actually
# specified. Idempotent — re-runs on next container restart pick up any
# UI subnet change.
ensure_masquerade

exec openvpn --config /etc/openvpn-dynamic/server.conf
