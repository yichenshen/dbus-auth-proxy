#!/bin/sh
# Installs the dbus-auth-proxy quadlet units for the current user, building the
# image from this checkout. Safe to re-run.
set -eu

script=$(readlink -f "$0")
repo=$(cd "$(dirname "$script")/.." && pwd -P)
dest=${XDG_CONFIG_HOME:-$HOME/.config}/containers/systemd

# Escape sed replacement metacharacters so the path is inserted literally.
repo_esc=$(printf '%s' "$repo" | sed 's/[&|\\]/\\&/g')

mkdir -p "$dest"
sed "s|@REPO_DIR@|$repo_esc|g" "$repo/quadlet/dbus-auth-proxy.build.in" \
  > "$dest/dbus-auth-proxy.build"
cp "$repo/quadlet/dbus-auth-proxy.container" "$dest/dbus-auth-proxy.container"
systemctl --user daemon-reload

echo "Installed quadlet units to $dest (build context: $repo)"
