#!/usr/bin/env bash
# Preserve upstream Go module notices for the exact pinned Gitleaks dependency set.
set -euo pipefail
output=$1
pins=$2
temporary=$(mktemp -d "$RUNNER_TEMP/vpremises-notices.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
revision=$(jq -r '.gitleaks.revision' "$pins")
curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-time 120 \
    "https://raw.githubusercontent.com/gitleaks/gitleaks/$revision/go.mod" -o "$temporary/go.mod"
printf '%s  %s\n' "$(jq -r '.gitleaks.go_mod_sha256' "$pins")" "$temporary/go.mod" | sha256sum -c --strict
cp "$temporary/go.mod" "$output/go.mod"
index=0
while read -r module version; do
    [[ "$version" =~ ^v[0-9a-zA-Z.+-]+$ && "$module" =~ ^[a-zA-Z0-9./_-]+$ ]] || exit 1
    escaped=$(awk -v name="$module" 'BEGIN {for(i=1;i<=length(name);i++){c=substr(name,i,1); printf "%s", c~/[A-Z]/?"!"tolower(c):c}}')
    archive="$temporary/module.zip"
    curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-time 120 --max-filesize 67108864 \
        "https://proxy.golang.org/$escaped/@v/$version.zip" -o "$archive"
    index=$((index+1))
    notice="$output/module-$index.txt"
    printf 'Module: %s\nVersion: %s\nArchive SHA-256: %s\n\n' "$module" "$version" "$(sha256sum "$archive" | cut -d ' ' -f1)" > "$notice"
    found=0
    while IFS= read -r member; do
        base=${member##*/}
        case "${base^^}" in
            LICENSE*|LICENCE*|COPYING*|NOTICE*|COPYRIGHT*)
                printf '\n--- %s ---\n' "$member" >> "$notice"
                unzip -p "$archive" "$member" >> "$notice"
                found=1
                ;;
        esac
    done < <(unzip -Z1 "$archive")
    [[ "$found" == 1 ]] || { printf 'Missing module notice: %s\n' "$module" >&2; exit 1; }
done < <(awk '$1~/^[a-zA-Z0-9]/ && $2~/^v[0-9]/ {print $1,$2}' "$temporary/go.mod")
[[ "$index" -gt 0 ]] || exit 1
