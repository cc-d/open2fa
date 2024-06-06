#!/bin/sh
set -e

SET_VER_DIR=$(cd "$(dirname $0)" && pwd)

echo "Using DIR: $SET_VER_DIR"

SET_VER_PY=$(find "$SET_VER_DIR" -name "version.py" -maxdepth 5 | head -n 1)
SET_VER_PROJ=$(find "$SET_VER_DIR" -name "pyproject.toml" -maxdepth 5 | head -n 1)

SET_VER_CURVER=$(cat "$SET_VER_PY" | grep -oE "= [\"'].*[\"']" | tr -d "'\"= ")

echo "version.py: $SET_VER_PY"
echo "pyproject.toml: $SET_VER_PROJ"
echo "Current version: $SET_VER_CURVER"

read -p "Enter New Version: " SET_VER_NEWVER

echo "Setting new version to: $SET_VER_NEWVER"

echo "Setting version in $SET_VER_PY"
echo "__version__ = '$SET_VER_NEWVER'" > "$SET_VER_PY"

echo "Setting version in $SET_VER_PROJ"
sed -E -i '' "s/^version = .*$/version = '$SET_VER_NEWVER'/" "$SET_VER_PROJ"
