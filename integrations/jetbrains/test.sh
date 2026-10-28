#!/usr/bin/env bash
# Compile the IDE-independent part (CliView) with the Java SDK's JSON reader
# and run its tests; needs only a JDK (16+).
set -euo pipefail
cd "$(dirname "$0")"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
javac -Xlint:all -d "$out" ../../sdk/java/src/main/java/io/kepr/Json.java ../../sdk/java/src/main/java/io/kepr/KeprException.java \
	src/main/java/io/kepr/CliView.java src/test/java/io/kepr/CliViewTest.java
java -cp "$out" io.kepr.CliViewTest
