#!/bin/bash
set -euo pipefail

burp_ext_root='/opt/pwn_burp'
java_home='/usr/lib/jvm/java-21-openjdk-amd64'
gradle_cache_dir="${burp_ext_root}/.gradle"
build_root="$burp_ext_root/build"
build_libs="$build_root/libs"
pwn_burp_backup="${burp_ext_root}.BAK"
burp_root='/opt/burpsuite'

# Pin Gradle runtime to Java 21 for this repo so future system Java changes
# (e.g. newer EA releases) do not break the build.
export JAVA_HOME="${java_home}"
export PATH="${JAVA_HOME}/bin:${PATH}"

cd "$burp_ext_root"

# If install.sh is run with sudo, build as the original user to avoid root-owned
# Gradle/build artifacts that later break non-sudo development commands.
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  BUILD_CMD=(sudo -u "${SUDO_USER}" env JAVA_HOME="${JAVA_HOME}" PATH="${PATH}" ./gradlew)
else
  BUILD_CMD=(./gradlew)
fi

if [[ -d "${gradle_cache_dir}" ]]; then
  echo "Stopping Gradle Daemon..."
  "${BUILD_CMD[@]}" --stop || true
fi

if [[ ! -d "${burp_root}" ]]; then
  echo "Creating ${burp_root} directory..."
  sudo mkdir -p "$burp_root"
fi

# Build the project
"${BUILD_CMD[@]}" clean build shadowJar

tree . > STRUCTURE.txt
sudo cp "${build_libs}/pwn-burp.jar" "$burp_root/pwn-burp.jar"

if [[ -d "${pwn_burp_backup}" ]]; then
  sudo rm -rf "${pwn_burp_backup}"
fi
sudo cp -a "${burp_ext_root}" "${pwn_burp_backup}"
