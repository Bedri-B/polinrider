#!/usr/bin/env bash
# polinrider_check_remote.sh — scan REMOTE GitHub repos for the config-injection worm WITHOUT cloning.
# Uses the git tree API (blob sizes come free) + fetches only suspect blobs to marker-scan.
# Requires: gh (authenticated), node or base64.
# Usage:
#   bash polinrider_check_remote.sh OWNER/REPO [OWNER/REPO ...]
#   bash polinrider_check_remote.sh --file repos.txt       # one OWNER/REPO per line
#   bash polinrider_check_remote.sh --all                  # every repo you can access
#   add --default-only to scan just the default branch (faster); default is ALL branches
#   Writes a TSV of findings to ./polinrider_remote_findings.tsv
set -u
BRANCHES_ALL=1; REPOS=(); TSV="./polinrider_remote_findings.tsv"
args=(); while [ $# -gt 0 ]; do case "$1" in
  --default-only) BRANCHES_ALL=0;;
  --file) shift; mapfile -t f < "$1"; REPOS+=("${f[@]}");;
  --all) mapfile -t f < <(gh api user/repos --paginate -X GET -f affiliation=owner,organization_member,collaborator -f per_page=100 --jq '.[].full_name'); REPOS+=("${f[@]}");;
  --out) shift; TSV="$1";;
  *) REPOS+=("$1");;
esac; shift; done

CONFIG_RE='(postcss|next|vite|tailwind|eslint|astro|vue|webpack|jest|svelte|nuxt|rollup|remix|drizzle)\.config\.(js|cjs|mjs|ts)$|(^|/)\.env($|\.)'
DROP_KEY="AUTH_API_""KEY"
MARKER_RE="A[0-9]-[0-9]{4}|C2[0-9]{5}A|RS2[0-9]{5}|_\\\$_[0-9a-f]{4,}|$DROP_KEY|auth-con-firm|a322e5f3d311d3080e6f0121063e9adc2490ef1a|createRequire|global\['"
SIZE_MAX=8000
red(){ printf '\033[31m%s\033[0m\n' "$*"; }; grn(){ printf '\033[32m%s\033[0m\n' "$*"; }
b64d(){ if command -v base64 >/dev/null; then base64 -d 2>/dev/null; else node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(Buffer.from(s,"base64")))'; fi; }

printf 'repo\tbranch\tpath\tsize\tsignal\tblob_sha\n' > "$TSV"
declare -A BLOB_CACHE   # sha -> signal (avoid refetching identical blobs)
INFECTED=()

scan_tree(){ # $1=full  $2=branch  $3=tip_sha
  local full="$1" br="$2" sha="$3" line size path bsha sig tree
  tree=$(gh api "repos/$full/git/trees/$sha?recursive=1" --jq '.tree[] | select(.type=="blob") | "\(.size)\t\(.path)\t\(.sha)"' 2>/dev/null)
  if [ -z "$tree" ]; then
    printf '\033[33m    WARN: empty/failed tree for %s@%s — NOT verified (retry this repo)\033[0m\n' "$full" "$br" >&2
    return
  fi
  while IFS=$'\t' read -r size path bsha; do
    [ -n "$path" ] || continue
    echo "$path" | grep -qEi "$CONFIG_RE" || continue
    sig=""
    if [ "${size:-0}" -gt "$SIZE_MAX" ]; then sig="SIZE-ANOMALY(${size}b)"; fi
    if [ -z "$sig" ]; then
      # small config or .env: fetch blob once and marker-scan
      if [ -n "${BLOB_CACHE[$bsha]+x}" ]; then sig="${BLOB_CACHE[$bsha]}"; else
        local content; content=$(gh api "repos/$full/git/blobs/$bsha" --jq '.content' 2>/dev/null | b64d)
        local hit; hit=$(printf '%s' "$content" | grep -oE "$MARKER_RE" | sort -u | paste -sd, -)
        [ -n "$hit" ] && sig="MARKER:$hit"
        BLOB_CACHE[$bsha]="$sig"
      fi
    fi
    if [ -n "$sig" ]; then
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$full" "$br" "$path" "$size" "$sig" "$bsha" >> "$TSV"
      echo "    [$sig] $br:$path"
      INFECTED+=("$full")
    fi
  done <<< "$tree"
}

echo "=== remote scan of ${#REPOS[@]} repo(s)  (branches: $([ $BRANCHES_ALL -eq 1 ] && echo ALL || echo default-only)) ==="
for full in "${REPOS[@]}"; do
  full=$(echo "$full" | tr -d ' \r'); [ -n "$full" ] || continue
  local_hits_before=${#INFECTED[@]}
  if [ "$BRANCHES_ALL" -eq 1 ]; then
    while IFS=$'\t' read -r br sha; do [ -n "$br" ] && scan_tree "$full" "$br" "$sha"; done \
      < <(gh api "repos/$full/branches" --paginate --jq '.[] | "\(.name)\t\(.commit.sha)"' 2>/dev/null)
  else
    db=$(gh api "repos/$full" --jq '.default_branch' 2>/dev/null)
    scan_tree "$full" "$db" "$db"
  fi
  [ ${#INFECTED[@]} -gt $local_hits_before ] && red "INFECTED $full" || grn "clean    $full"
done
echo
# dedup infected list
mapfile -t UNIQ < <(printf '%s\n' "${INFECTED[@]}" | sort -u)
echo "=========================================="
echo "infected repos: ${#UNIQ[@]}   (findings TSV: $TSV)"
printf '  %s\n' "${UNIQ[@]}"
