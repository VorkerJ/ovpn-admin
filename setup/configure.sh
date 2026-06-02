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

iptables -t nat -D POSTROUTING -s ${OVPN_SRV_NET}/${OVPN_SRV_MASK} ! -d ${OVPN_SRV_NET}/${OVPN_SRV_MASK} -j MASQUERADE || true
iptables -t nat -A POSTROUTING -s ${OVPN_SRV_NET}/${OVPN_SRV_MASK} ! -d ${OVPN_SRV_NET}/${OVPN_SRV_MASK} -j MASQUERADE || echo "WARN: iptables MASQUERADE failed (Docker Desktop?). VPN clients won't have internet access."

mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200
fi

# NOTE: per-user password-auth directives must be in the user-editable
# server config (added via ovpn-admin UI's Дополнительно textarea), e.g.:
#   auth-user-pass-verify /etc/openvpn/scripts/auth.sh via-file
#   script-security 2
#   verify-client-cert require
# This used to be appended here automatically when OVPN_PASSWD_AUTH=true,
# but rendered config is now owned by ovpn-admin. The auth.sh script is
# still copied below so manually adding the directives works.
if [ ${OVPN_PASSWD_AUTH} = "true" ]; then
  mkdir -p /etc/openvpn/scripts/
  cp -f /etc/openvpn/setup/auth.sh /etc/openvpn/scripts/auth.sh
  chmod +x /etc/openvpn/scripts/auth.sh
  openvpn-user db-init --db.path=$EASY_RSA_LOC/pki/users.db && openvpn-user db-migrate --db.path=$EASY_RSA_LOC/pki/users.db
fi

[ -d $EASY_RSA_LOC/pki ] && chmod 755 $EASY_RSA_LOC/pki
[ -f $EASY_RSA_LOC/pki/crl.pem ] && chmod 644 $EASY_RSA_LOC/pki/crl.pem

# The rendered server.conf references /etc/openvpn/pki — point it at easyrsa's pki
[ ! -e /etc/openvpn/pki ] && ln -s $EASY_RSA_LOC/pki /etc/openvpn/pki

mkdir -p /etc/openvpn/ccd

# server.conf is now rendered by ovpn-admin into /etc/openvpn-dynamic/server.conf
# Allow ovpn-admin (non-root, member of GID 2000) to write here.
# 0770 = root + ovpnshared group only, no world access.
addgroup -g 2000 ovpnshared 2>/dev/null || true
chown root:2000 /etc/openvpn-dynamic 2>/dev/null || true
chmod 0770 /etc/openvpn-dynamic 2>/dev/null || true
echo "Waiting for ovpn-admin to render server.conf..."
until [ -f /etc/openvpn-dynamic/server.conf ]; do
  sleep 1
done

exec openvpn --config /etc/openvpn-dynamic/server.conf
