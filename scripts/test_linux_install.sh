#!/usr/bin/env bash
# Install and launch release artifacts in a disposable Debian/Ubuntu container.
set -euo pipefail

if [[ ! -f /.dockerenv || $(id -u) != 0 ]]; then
  echo "Run this check as root inside a disposable container." >&2
  exit 1
fi
artifacts=$(realpath "${1:?installer artifact directory is required}")
output=$(realpath -m "${2:?test output directory is required}")
format=${3:?deb or appimage is required}
case "$format" in deb|appimage) ;; *) exit 2 ;; esac
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
export DEBIAN_FRONTEND=noninteractive
apt-get update
if [[ $format == deb ]]; then
  packages=("$artifacts"/deb/*.deb)
  [[ ${#packages[@]} == 1 && -f ${packages[0]} ]]
  apt-get install -y --no-install-recommends "${packages[0]}"
  package=$(dpkg-deb --field "${packages[0]}" Package)
  executable=/usr/bin/openaidr-desktop
  # Check dependencies before installing GUI test tools, which can mask omissions.
  ldd "$executable" | tee /tmp/openaidr-dependencies.txt
  if grep -q 'not found' /tmp/openaidr-dependencies.txt; then exit 1; fi
  version=$(dpkg-deb --field "${packages[0]}" Version)
  [[ $(PYTHONTZPATH=/nonexistent /usr/bin/openaidr version) == "openaidr $version" ]]
else
  # Graphics drivers come from the host, not the AppImage. No WebKit, Python
  # project, or FUSE is installed to satisfy the packaged app's dependencies.
  apt-get install -y --no-install-recommends libgtk-3-0 libayatana-appindicator3-1 \
    libegl1 libgbm1 libgl1 libgles2 libgl1-mesa-dri ca-certificates
fi
apt-get install -y --no-install-recommends python3 python3-pyatspi xvfb xauth dbus-x11
useradd --create-home --shell /bin/bash openaidr-test
mkdir -p "$output"
chown openaidr-test:openaidr-test "$output"
if [[ $format == appimage ]]; then
  images=("$artifacts"/appimage/*.AppImage)
  [[ ${#images[@]} == 1 && -f ${images[0]} ]]
  executable=/home/openaidr-test/OpenAIDR.AppImage
  install -m 755 -o openaidr-test -g openaidr-test "${images[0]}" "$executable"
fi
runuser -u openaidr-test -- xvfb-run -a dbus-run-session -- \
  python3 "$script_dir/test_linux_startup.py" "$executable" "$output" "$format"
if [[ $format == deb ]]; then
  apt-get remove -y "$package"
  [[ ! -e $executable ]]
else
  rm "$executable"
fi
printf '%s installation, first launch, and removal passed.\n' "$format"
