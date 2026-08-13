#!/usr/bin/env bash
# Proves check-shell-prose.sh can actually go RED, and does not go red on
# working code.
#
# A guard that cannot fail is worse than no guard: it produces a green tick
# that means nothing. This repository already learned that once -- the first
# version of check-no-internal-topology.sh used an invalid grep flag and
# passed on a tree that DID contain internal addresses -- so every checker
# here ships with a test that mutates a file and demands a red.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/check-shell-prose.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail=0

# Fixtures are built with $H instead of a literal '#'. THIS IS NOT COSMETIC:
# the first version of this test wrote the fixtures literally, so the bogus
# prose line sat in the source sandwiched between two real comment lines --
# and the repo-wide scan flagged THIS FILE. CI caught it (job red), which is
# exactly what the job is for. The generated file is byte-identical; only the
# source stops looking like the defect it describes.
H='#'

t() { # name expected_rc file_content
  local name="$1" exp="$2"; shift 2
  printf '%s' "$1" > "$WORK/case.sh"
  bash "$CHECK" "$WORK/case.sh" >/dev/null 2>&1
  local rc=$?
  if [ "$rc" = "$exp" ]; then
    echo "ok   $name (rc=$rc)"
  else
    echo "FAIL $name (rc=$rc, beklenen $exp)"; fail=$((fail+1))
  fi
}

# MUST GO RED: this is the real defect, reproduced. A comment lost its '#',
# `bash -n` still passes, and the script silently runs a bogus command.
t "kayip-# yakalanir" 1 "$H!/usr/bin/env bash
$H yorum satiri burada
THIS GATE IS DETERMINISTIC. It was not at first, so it lied.
$H yorum devam ediyor
echo hi
"

# MUST STAY GREEN: real code that happens to be four metacharacter-free
# words between two comments. The first version of the checker flagged this,
# which is how the "known command" and "prose punctuation" rules were born.
# A checker that flags a working line teaches people to pass --no-verify.
t "rm satiri yanlis-pozitif degil" 0 "$H!/usr/bin/env bash
$H yorum
rm -rf build dist node_modules
$H yorum
"

# MUST STAY GREEN: prose punctuation, but it is a genuine command.
t "docker satiri yanlis-pozitif degil" 0 "$H!/usr/bin/env bash
$H yorum
docker compose up -d, then wait.
$H yorum
"

# MUST STAY GREEN: a normal, correctly commented file.
t "dogru yorumlanmis dosya temiz" 0 "$H!/usr/bin/env bash
$H This is a perfectly normal comment, with punctuation.
$H And a second one, also fine.
set -e
echo done
"

# MUST STAY GREEN: short non-comment line between comments (e.g. `fi`).
t "kisa satir tetiklemez" 0 "$H!/usr/bin/env bash
$H yorum
fi
$H yorum
"

if [ "$fail" -gt 0 ]; then
  echo "PROSE_CHECK_SELFTEST=FAILED($fail)"; exit 1
fi
echo "PROSE_CHECK_SELFTEST=OK"
