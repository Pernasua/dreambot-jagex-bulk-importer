#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$ROOT/src"
LIB="$ROOT/lib"
BUILD="$ROOT/build"
CLASSES="$BUILD/classes"
DIST="$ROOT/dist"
MAIN="com.pernasua.dreambot.jageximporter.DreamBotJagexBulkImporter"
JAR="$DIST/dreambot-jagex-bulk-importer.jar"
MANIFEST="$BUILD/MANIFEST.MF"

rm -rf "$CLASSES"
mkdir -p "$CLASSES" "$DIST"

CP=""
if compgen -G "$LIB/*.jar" >/dev/null; then
  CP="$(find "$LIB" -name '*.jar' ! -name 'jcef-natives-*.jar' | sort | paste -sd: -)"
fi

if [[ -n "$CP" ]]; then
  javac --release 11 -cp "$CP" -d "$CLASSES" $(find "$SRC" -name '*.java' | sort)
  while IFS= read -r dep; do
    (cd "$CLASSES" && jar xf "$dep")
  done < <(find "$LIB" -name '*.jar' ! -name 'jcef-natives-*.jar' | sort)
  find "$CLASSES/META-INF" -type f \( -name '*.SF' -o -name '*.RSA' -o -name '*.DSA' \) -delete 2>/dev/null || true
else
  javac --release 11 -d "$CLASSES" $(find "$SRC" -name '*.java' | sort)
fi

cat >"$MANIFEST" <<EOF
Main-Class: $MAIN
EOF

jar cfm "$JAR" "$MANIFEST" -C "$CLASSES" .
chmod 0755 "$JAR"
echo "$JAR"
