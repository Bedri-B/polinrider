#!/usr/bin/env bash
# polinrider_fix.sh — remediate config-injection worm in the WORKING TREE. Safe by default.
#   DRY-RUN (default): writes cleaned copies to <file>.cleaned and prints a diff. Changes nothing.
#   --apply          : overwrites the real files with the cleaned content.
# It NEVER runs git add/commit/push. After --apply, review `git diff`, commit, and force-push yourself.
#
# Cleaning strategy per infected config file:
#   1) Prefer restoring the newest PRE-INFECTION version of the file from git history (clean blob).
#   2) If no clean history exists, reconstruct: drop payload line(s) (>400 chars) + trim 80+ space runs,
#      and remove an injected `createRequire` prelude when the body doesn't otherwise use require().
# .env files: strip lines containing the dropper key (delete the file if that was its only content).
#
# Usage:  bash polinrider_fix.sh [--apply] [ROOT ...]
set -u
APPLY=0; ROOTS=()
for a in "$@"; do case "$a" in --apply) APPLY=1;; *) ROOTS+=("$a");; esac; done
[ ${#ROOTS[@]} -eq 0 ] && ROOTS=(".")

CONFIG_GLOB='(postcss|next|vite|tailwind|eslint|astro|vue|webpack|jest|svelte|nuxt|rollup|remix|drizzle)\.config\.(js|cjs|mjs|ts)$'
DROP_KEY="AUTH_API_""KEY"
SIZE_MAX=8000; LINE_MAX=400
MARKER_RE="A[0-9]-[0-9]{4}|C2[0-9]{5}A|RS2[0-9]{5}|_\\\$_[0-9a-f]{4,}|$DROP_KEY|auth-con-firm|a322e5f3d311d3080e6f0121063e9adc2490ef1a"
red(){ printf '\033[31m%s\033[0m\n' "$*"; }; grn(){ printf '\033[32m%s\033[0m\n' "$*"; }; ylw(){ printf '\033[33m%s\033[0m\n' "$*"; }

is_infected_blob(){ # stdin -> 0 if looks infected
  local c; c=$(cat); local b l
  b=$(printf '%s' "$c" | wc -c); l=$(printf '%s' "$c" | awk '{if(length>m)m=length}END{print m+0}')
  { [ "$b" -gt "$SIZE_MAX" ] || [ "$l" -gt "$LINE_MAX" ] || printf '%s' "$c" | grep -qE "$MARKER_RE"; }
}

reconstruct(){ # stdin(payloaded file) -> stdout(cleaned)
  awk -v L="$LINE_MAX" 'length<=L' | sed -E 's/[[:space:]]{80,}.*$//' \
  | awk '
    NR<=3 && $0 ~ /createRequire *\( *import\.meta\.url *\)/ {cr=1}
    NR<=3 && $0 ~ /import[ {].*createRequire.*from .module./ {imp=NR; next}
    NR<=3 && $0 ~ /const +require *= *createRequire/ {crl=NR; next}
    {lines[NR]=$0}
    END{
      body=""; for(i=1;i<=NR;i++) if(i!=imp && i!=crl) body=body lines[i] "\n";
      if((imp||crl) && body !~ /require *\(/){ printf "%s", body }      # prelude was injected & unused -> drop
      else { for(i=1;i<=NR;i++) print lines[i] }                        # keep as-is otherwise
    }'
}

clean_config(){ # $1=abs file, $2=repo, $3=relpath
  local file="$1" repo="$2" rel="$3" good="" h sz
  is_infected_blob < "$file" || return 1
  # (1) newest clean historical version
  while IFS= read -r h; do
    sz=$(git -C "$repo" cat-file -s "$h:$rel" 2>/dev/null) || continue
    [ "${sz:-99999}" -le "$SIZE_MAX" ] || continue
    if ! git -C "$repo" show "$h:$rel" 2>/dev/null | grep -qE "$MARKER_RE"; then good="$h"; break; fi
  done < <(git -C "$repo" log --all --format=%H -- "$rel" 2>/dev/null)

  local tmp="$file.cleaned"
  if [ -n "$good" ]; then
    git -C "$repo" show "$good:$rel" > "$tmp" 2>/dev/null
    ylw "  fix $rel  <- restore from clean commit ${good:0:9}"
  else
    reconstruct < "$file" > "$tmp"
    ylw "  fix $rel  <- reconstructed (no clean history found; REVIEW CAREFULLY)"
  fi
  echo "      before=$(wc -c <"$file")b  after=$(wc -c <"$tmp")b"
  if [ "$APPLY" -eq 1 ]; then mv "$tmp" "$file"; grn "      applied"; else echo "      (dry-run: wrote $tmp)"; fi
}

clean_env(){ # $1=abs .env  $2=rel
  grep -qF "$DROP_KEY" "$1" 2>/dev/null || return 1
  ylw "  fix $2  <- strip $DROP_KEY line"
  local tmp="$1.cleaned"; grep -vF "$DROP_KEY" "$1" > "$tmp"
  if [ "$APPLY" -eq 1 ]; then
    if [ -s "$tmp" ]; then mv "$tmp" "$1"; else rm -f "$tmp" "$1"; echo "      removed empty .env"; fi
    grn "      applied"
  else echo "      (dry-run: wrote $tmp)"; fi
}

echo "=== PolinRider fixer  (mode: $([ $APPLY -eq 1 ] && echo APPLY || echo DRY-RUN)) ==="
mapfile -t REPOS < <(for r in "${ROOTS[@]}"; do find "$r" -type d -name .git -prune 2>/dev/null | sed 's#/\.git$##'; done | sort -u)
for repo in "${REPOS[@]}"; do
  touched=0
  while IFS= read -r rel; do
    [ -n "$rel" ] || continue
    clean_config "$repo/$rel" "$repo" "$rel" && touched=1
  done < <(git -C "$repo" ls-files 2>/dev/null | grep -Ei "$CONFIG_GLOB")
  while IFS= read -r rel; do
    [ -n "$rel" ] || continue
    clean_env "$repo/$rel" "$rel" && touched=1
  done < <(git -C "$repo" ls-files 2>/dev/null | grep -E '(^|/)\.env')
  [ "$touched" -eq 1 ] && { echo "  repo: $repo"; echo; }
done
echo "=========================================="
echo "Next: in each fixed repo, run 'git diff' to verify, then commit the cleaned files."
echo "To also purge the malicious commits from history (recommended), reset to the last known-good"
echo "commit and force-push, e.g.:  git reset --hard <good-sha> && git push --force-with-lease"
[ $APPLY -eq 0 ] && ylw "This was a DRY-RUN. Re-run with --apply to modify files."
