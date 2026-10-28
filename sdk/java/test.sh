#!/usr/bin/env bash
# Compile the client and run the fake-daemon tests; needs only a JDK (16+).
set -euo pipefail
cd "$(dirname "$0")"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
javac -Xlint:all -d "$out" src/main/java/io/kepr/*.java src/test/java/io/kepr/*.java
java -cp "$out" io.kepr.KeprTest
