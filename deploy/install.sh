#!/bin/sh
# Rostor appliance installer for Debian 12/13 and Ubuntu 24.04.
#
#   curl -fsSL https://raw.githubusercontent.com/rostor-org/app/main/deploy/install.sh | sudo sh
#
# Private repository: export ROSTOR_CHANNEL_TOKEN=<GitHub token with repo read>
# before running (it is also stored in /etc/rostor/env for the updater).
#
# Idempotent: re-running upgrades the binary and repairs units; it never
# touches the database, the master key, or the admin token.
set -eu

REPO="${ROSTOR_REPO:-rostor-org/app}"
CHANNEL="${ROSTOR_CHANNEL:-stable}"
CHANNEL_URL="${ROSTOR_CHANNEL_URL:-https://raw.githubusercontent.com/$REPO/main/deploy/channels/$CHANNEL.json}"
PUBKEY_URL="${ROSTOR_PUBKEY_URL:-https://raw.githubusercontent.com/$REPO/main/deploy/release.pub}"
UNITS_URL="${ROSTOR_UNITS_URL:-https://raw.githubusercontent.com/$REPO/main/deploy/systemd}"
TOKEN="${ROSTOR_CHANNEL_TOKEN:-}"
TENANT="${ROSTOR_TENANT:-rostor}"

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
fetch() { # url dest
  if [ -n "$TOKEN" ]; then
    curl -fsSL -H "Authorization: Bearer $TOKEN" -H "Accept: application/octet-stream" -o "$2" "$1"
  else
    curl -fsSL -H "Accept: application/octet-stream" -o "$2" "$1"
  fi
}

[ "$(id -u)" = 0 ] || die "run as root (sudo sh)"
command -v systemctl >/dev/null || die "systemd is required"
. /etc/os-release
case "$ID:$VERSION_ID" in
  debian:12|debian:13|ubuntu:24.04) ;;
  *) die "unsupported OS: $PRETTY_NAME (supported: Debian 12/13, Ubuntu 24.04)";;
esac
ARCH="$(dpkg --print-architecture)"
case "$ARCH" in amd64|arm64) ;; *) die "unsupported architecture $ARCH";; esac

say "Installing prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates postgresql >/dev/null
systemctl enable --now postgresql >/dev/null

say "Creating rostor user, directories and database"
id rostor >/dev/null 2>&1 || useradd --system --home /var/lib/rostor --shell /usr/sbin/nologin rostor
install -d -o rostor -g rostor -m 0750 /var/lib/rostor
install -d -m 0755 /etc/rostor
cd /; su postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='rostor'\"" | grep -q 1 || su postgres -c "createuser rostor"
su postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='rostor'\"" | grep -q 1 || su postgres -c "createdb -O rostor rostor"

say "Pinning the release signing key"
fetch "$PUBKEY_URL" /etc/rostor/release.pub.new
[ "$(wc -c < /etc/rostor/release.pub.new)" -ge 64 ] || die "release.pub looks wrong"
if [ -f /etc/rostor/release.pub ] && ! cmp -s /etc/rostor/release.pub /etc/rostor/release.pub.new; then
  die "release.pub differs from the pinned key; refusing to change trust silently. Remove /etc/rostor/release.pub to accept the new key."
fi
mv /etc/rostor/release.pub.new /etc/rostor/release.pub

if [ ! -f /etc/rostor/env ]; then
  say "Writing /etc/rostor/env"
  cat > /etc/rostor/env <<ENV
ROSTOR_DATABASE_URL=postgres:///rostor?host=/var/run/postgresql
ROSTOR_DATA_DIR=/var/lib/rostor
ROSTOR_STATE_DIR=/var/lib/rostor
ROSTOR_LISTEN=:8443
ROSTOR_ADMIN_LISTEN=:8080
ROSTOR_TRUSTED_PROXIES=
ROSTOR_TLS_HOSTS=
ROSTOR_CHANNEL_URL=$CHANNEL_URL
ROSTOR_CHANNEL_TOKEN=$TOKEN
ROSTOR_RELEASE_PUBKEY=/etc/rostor/release.pub
ENV
  chmod 0640 /etc/rostor/env; chgrp rostor /etc/rostor/env
fi

say "Fetching the $CHANNEL channel manifest"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fetch "$CHANNEL_URL" "$TMP/manifest.json"
VERSION="$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$TMP/manifest.json" | head -1)"
URL="$(tr -d '\n' < "$TMP/manifest.json" | sed -n "s/.*\"linux-$ARCH\": *{[^}]*\"url\": *\"\([^\"]*\)\".*/\1/p")"
SHA="$(tr -d '\n' < "$TMP/manifest.json" | sed -n "s/.*\"linux-$ARCH\": *{[^}]*\"sha256\": *\"\([^\"]*\)\".*/\1/p")"
[ -n "$VERSION" ] && [ -n "$URL" ] && [ -n "$SHA" ] || die "manifest has no linux-$ARCH entry"

say "Downloading rostor $VERSION"
fetch "$URL" "$TMP/rostor"
echo "$SHA  $TMP/rostor" | sha256sum -c --quiet - || die "sha256 mismatch on downloaded binary"
chmod 0755 "$TMP/rostor"
# The manifest signature itself is verified by the binary we just checked by
# digest; the digest came from the manifest, so verify the signature now
# before trusting anything further.
env ROSTOR_DATA_DIR=/var/lib/rostor ROSTOR_STATE_DIR="$TMP" ROSTOR_RELEASE_PUBKEY=/etc/rostor/release.pub \
  "$TMP/rostor" update check --channel-url "$CHANNEL_URL" ${TOKEN:+--token "$TOKEN"} >/dev/null \
  || die "channel manifest failed signature verification"
install -m 0755 "$TMP/rostor" /usr/local/bin/rostor

say "Installing systemd units"
for u in rostor.service rostor-update-check.service rostor-update-check.timer rostor-update.path rostor-update.service; do
  fetch "$UNITS_URL/$u" "/etc/systemd/system/$u"
done
systemctl daemon-reload

if ! su rostor -s /bin/sh -c "ROSTOR_DATABASE_URL='postgres:///rostor?host=/var/run/postgresql' psql -tAc \"SELECT 1 FROM tenants LIMIT 1\" rostor" 2>/dev/null | grep -q 1; then
  say "Bootstrapping tenant '$TENANT' (one-time)"
  set -a; . /etc/rostor/env; set +a
  su rostor -s /bin/sh -c "/usr/local/bin/rostor bootstrap --tenant '$TENANT'" | tee /var/lib/rostor/bootstrap.out
  chmod 0600 /var/lib/rostor/bootstrap.out; chown rostor:rostor /var/lib/rostor/bootstrap.out
  echo "The admin token above is also in /var/lib/rostor/bootstrap.out (root/rostor only); delete that file once stored."
fi

say "Starting services"
systemctl enable --now rostor.service rostor-update-check.timer rostor-update.path >/dev/null
systemctl restart rostor.service
sleep 1
systemctl --no-pager --lines=3 status rostor.service | sed -n '1,4p'

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
say "Rostor $VERSION is installed"
echo "  devices:  https://$IP:8443   (mutual TLS; CA at /var/lib/rostor/ca.crt)"
echo "  admin:    http://$IP:8080    (put a TLS-terminating proxy in front)"
echo "  updates:  rostor admin update status   |   rostor update apply (root)"
