#!/usr/bin/env bash
# Catches prose that lost its leading '#' inside a shell script.
#
# WHY THIS EXISTS: a comment line in run-fault-matrix.sh lost its '#' while I
# was editing the file. The result was still SYNTACTICALLY VALID, so `bash -n`
# passed, the test suite printed 6/6, and the only trace was one line of
# stderr:  "THIS: command not found". It went unnoticed for two merged PRs and
# I found it only by chance, running the script in a fresh clone.
#
# That is the dangerous shape: a script that keeps reporting success while
# quietly executing garbage. Under `set -e` the same slip one line lower would
# have killed the run instead.
#
# THE RULE IS DELIBERATELY NARROW. It fires only when a line is:
#   - not a comment, and
#   - sandwiched between comment lines (so it was almost certainly a comment), and
#   - four or more words, and
#   - free of shell metacharacters ($ = ( ) ; | & < > ` { } [ ]), and
#   - NOT starting with a known command, and
#   - carrying prose punctuation (a ',' or a sentence-ending '.')
# The last two rules came from a false positive the first version produced on
# real code: "rm -rf build dist node_modules" is four metacharacter-free words.
# A checker that flags a working line teaches people to pass --no-verify.
# A broad "does this look like English" check would fire on real code, get
# disabled within a week, and then protect nothing.
#
# Usage: bash scripts/check-shell-prose.sh [file...]     (default: repo shell files)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

files=("$@")
if [ "${#files[@]}" -eq 0 ]; then
  mapfile -t files < <(git -C "$ROOT" ls-files '*.sh' | sed "s#^#$ROOT/#")
fi

bad=0
for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  out="$(awk '
    { line[NR] = $0 }
    END {
      for (i = 2; i < NR; i++) {
        cur = line[i]
        if (cur ~ /^[[:space:]]*#/) continue          # already a comment
        if (cur ~ /^[[:space:]]*$/) continue          # blank
        if (line[i-1] !~ /^[[:space:]]*#/) continue   # not inside a comment block
        if (line[i+1] !~ /^[[:space:]]*#/) continue
        if (cur ~ /[$=();|&<>`{}\[\]]/) continue      # looks like real shell
        n = split(cur, w, /[[:space:]]+/)
        if (n < 4) continue                           # too short to be prose
        first = w[1]
        sub(/^[[:space:]]+/, "", first)
        if (first ~ /^(rm|cp|mv|cd|echo|set|export|source|git|docker|go|python3?|npm|npx|bash|sh|sudo|chmod|chown|mkdir|touch|cat|grep|sed|awk|curl|wget|kubectl|helm|terraform|make|exit|return|shift|read|wait|kill|sleep|printf|trap|local|declare|unset|ziti)$/) continue
        if (cur !~ /,|\.[[:space:]]|\.$/) continue     # no prose punctuation
        printf "%s:%d: %s\n", FILENAME, i, cur
      }
    }
  ' "$f")"
  if [ -n "$out" ]; then echo "$out"; bad=$((bad+1)); fi
done

if [ "$bad" -gt 0 ]; then
  echo "PROSE_IN_SHELL=$bad file(s): a comment probably lost its leading '#'"
  exit 1
fi
echo "PROSE_IN_SHELL=0"
