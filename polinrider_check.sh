#!/usr/bin/env bash
# polinrider_check.sh — READ-ONLY detector for the PolinRider / auth-con-firm config-injection worm.
# Scans working tree AND full git history of every repo under the given roots.
# Usage:  bash polinrider_check.sh [ROOT ...]        (default root: current dir)
#         bash polinrider_check.sh ~/Projects /c/tmp
# Exit code 2 if anything infected, 0 if clean.
set -u

ROOTS=("$@"); [ ${#ROOTS[@]} -eq 0 ] && ROOTS=(".")

# Config files the worm targets (whitespace-injection variant appends after the legit export)
CONFIG_GLOB='(postcss|next|vite|tailwind|eslint|astro|vue|webpack|jest|svelte|nuxt|rollup|remix|drizzle)\.config\.(js|cjs|mjs|ts)$'

# High-signal literal markers (both variants). Pickaxed through history and grepped in the tree.
DROP_KEY="AUTH_API_""KEY"                 # split so this file itself stays clean of the marker
EV_MARK="eval""(proxyInfo)"               # ditto
MARKERS=(
  "A9-4091" "A4-1928" "'4-1928'" "RS260605"
  "$DROP_KEY" "auth-con-firm" "aHR0cHM6Ly9hdXRoLWNvbi1maXJt" "$EV_MARK"
  "a322e5f3d311d3080e6f0121063e9adc2490ef1a"
  "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP" "TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG"
  "bsc-dataseed" "trongrid"
)
# Date-coded build-ID markers, matched by regex in the tree
MARKER_RE="A[0-9]-[0-9]{4}|C2[0-9]{5}A|RS2[0-9]{5}|global\['[^']'\]=require|_\\\$_[0-9a-f]{4,}"

INFECTED_REPOS=();
red(){ printf '\033[31m%s\033[0m\n' "$*"; }; grn(){ printf '\033[32m%s\033[0m\n' "$*"; }; ylw(){ printf '\033[33m%s\033[0m\n' "$*"; }

scan_repo(){
  local repo="$1" hits=0 out=""

  # ---- 1) WORKING-TREE: oversized / whitespace-padded config files ----
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    local bytes maxlen spaces
    bytes=$(wc -c < "$f" 2>/dev/null | tr -d ' ')
    maxlen=$(awk '{ if (length>m) m=length } END{ print m+0 }' "$f" 2>/dev/null)
    spaces=$(grep -oE ' {80,}' "$f" 2>/dev/null | head -1 | wc -c | tr -d ' ')
    # Payload always creates a very long line or a big whitespace run; raw size alone is noisy
    # (legit configs are commonly 2-6 KB), so require line/whitespace signal or an extreme size.
    if [ "${bytes:-0}" -gt 8000 ] || [ "${maxlen:-0}" -gt 400 ] || [ "${spaces:-0}" -gt 80 ]; then
      out+="    [CONFIG-ANOMALY] $f  (bytes=$bytes maxline=$maxlen wsrun=$spaces)"$'\n'
      hits=$((hits+1))
    fi
  done < <(git -C "$repo" ls-files 2>/dev/null | grep -Ei "$CONFIG_GLOB" | sed "s#^#$repo/#")

  # ---- 2) WORKING-TREE: literal markers in any tracked file ----
  local m grephit
  for m in "${MARKERS[@]}"; do
    grephit=$(git -C "$repo" grep -l -F -- "$m" 2>/dev/null)
    if [ -n "$grephit" ]; then
      out+="    [MARKER '$m'] "$(echo "$grephit" | paste -sd, -)$'\n'; hits=$((hits+1))
    fi
  done
  grephit=$(git -C "$repo" grep -lE -- "$MARKER_RE" 2>/dev/null)
  [ -n "$grephit" ] && { out+="    [REGEX-MARKER] "$(echo "$grephit" | paste -sd, -)$'\n'; hits=$((hits+1)); }

  # ---- 3) .env dropper (auth-con-firm variant) ----
  grephit=$(git -C "$repo" grep -lF "$DROP_KEY" 2>/dev/null)
  [ -n "$grephit" ] && out+="    [ENV-DROPPER] $grephit"$'\n'

  # ---- 4) HISTORY: pickaxe key markers across ALL refs (catches buried/amended commits) ----
  local term commits
  for term in "A9-4091" "$DROP_KEY" "a322e5f3d311d3080e6f0121063e9adc2490ef1a" "RS260605"; do
    commits=$(git -C "$repo" log --all -S "$term" --oneline 2>/dev/null | head -5)
    if [ -n "$commits" ]; then
      out+="    [HISTORY '$term']"$'\n'"$(echo "$commits" | sed 's/^/        /')"$'\n'; hits=$((hits+1))
    fi
  done

  # ---- 5) HISTORY: commits with foreign committer timezone (-0600) authored as you ----
  local tz
  tz=$(git -C "$repo" log --all --pretty='%cI|%h|%an|%s' 2>/dev/null | grep -- '-06:00' | grep -iE '\|Bedri' | head -5)
  [ -n "$tz" ] && out+="    [FOREIGN-TZ -06:00]"$'\n'"$(echo "$tz" | sed 's/^/        /')"$'\n'

  if [ "$hits" -gt 0 ]; then
    red "INFECTED  $repo"; INFECTED_REPOS+=("$repo"); printf '%s' "$out"
  elif [ -n "$out" ]; then
    ylw "SUSPECT   $repo"; printf '%s' "$out"
  else
    grn "clean     $repo"
  fi
}

echo "=== PolinRider / auth-con-firm checker ==="
mapfile -t REPOS < <(for r in "${ROOTS[@]}"; do find "$r" -type d -name .git -prune 2>/dev/null | sed 's#/\.git$##'; done | sort -u)
echo "scanning ${#REPOS[@]} repositories under: ${ROOTS[*]}"; echo
for r in "${REPOS[@]}"; do scan_repo "$r"; done
echo
echo "=========================================="
if [ ${#INFECTED_REPOS[@]} -gt 0 ]; then
  red "INFECTED: ${#INFECTED_REPOS[@]} repo(s)"; printf '  %s\n' "${INFECTED_REPOS[@]}"; exit 2
else
  grn "No infections found in ${#REPOS[@]} repos."
fi
