#!/usr/bin/env bash
#
# audit-listening-ports.test.sh — denetim betiğinin kendisini test eder.
#
# Bir güvenlik denetim betiğinin en tehlikeli hatası, sessizce hiçbir şey
# bulmayıp "temiz" raporlamasıdır. Bu testler betiğin hem yeşile hem
# kırmızıya gidebildiğini kanıtlar.

set -uo pipefail
cd "$(dirname "$0")/.."

SCRIPT="scripts/audit-listening-ports.sh"
pass=0
fail=0

ok()   { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  FAIL %s\n' "$1"; }

check() {
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then ok "$name"
  else bad "$name (beklenen: $expected, gelen: $actual)"; fi
}

if ! command -v ss >/dev/null 2>&1; then
  echo "SKIP: 'ss' yok, bu testler çalıştırılamaz." >&2
  exit 0
fi

echo "audit-listening-ports.sh testleri"

# --- 1. Betik çalışabilir ve sözdizimi geçerli ---
bash -n "$SCRIPT" 2>/dev/null
check "sözdizimi geçerli" 0 $?

[ -x "$SCRIPT" ]
check "çalıştırılabilir bit var" 0 $?

# Şu an tüm arayüzlerde dinleyen portlar.
mapfile -t current < <(
  ss -tlnH 2>/dev/null | awk '{print $4}' \
    | grep -E '^(0\.0\.0\.0|\*|\[::\]):' | grep -oE '[0-9]+$' | sort -n -u
)
all_ports="${current[*]:-}"

# --- 2. Her şeye izin verilirse temiz çıkmalı (yanlış pozitif yok) ---
ALLOW_PUBLIC="$all_ports" "$SCRIPT" >/dev/null 2>&1
check "hepsine izin verilince çıkış kodu 0" 0 $?

# --- 3. Hiçbir şeye izin verilmezse ve açık port varsa bulgu vermeli ---
if [ -n "$all_ports" ]; then
  ALLOW_PUBLIC="" "$SCRIPT" >/dev/null 2>&1
  check "izin listesi boşken çıkış kodu 1" 1 $?
else
  ok "açık port yok, bu test atlandı"
fi

# --- 4. KANARYA: yeni açılan bir port yakalanmalı ---
# Bu, betiğin gerçekten kırmızıya gidebildiğinin kanıtıdır.
CANARY_PORT=29997
python3 - "$CANARY_PORT" <<'PY' &
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.listen(1)
time.sleep(15)
PY
canary_pid=$!
sleep 2

if ss -tlnH 2>/dev/null | grep -qE "(0\.0\.0\.0|\*):${CANARY_PORT}\b"; then
  out=$(ALLOW_PUBLIC="$all_ports" "$SCRIPT" 2>&1)
  grep -q "$CANARY_PORT" <<<"$out"
  check "kanarya portu ($CANARY_PORT) raporlandı" 0 $?

  ALLOW_PUBLIC="$all_ports" "$SCRIPT" >/dev/null 2>&1
  check "kanarya varken çıkış kodu 1" 1 $?

  # Kanarya izin listesine eklenirse tekrar temiz olmalı.
  ALLOW_PUBLIC="$all_ports $CANARY_PORT" "$SCRIPT" >/dev/null 2>&1
  check "kanarya izin listesine eklenince çıkış kodu 0" 0 $?
else
  bad "kanarya portu açılamadı (test ortamı kısıtlı olabilir)"
fi

kill "$canary_pid" 2>/dev/null
wait "$canary_pid" 2>/dev/null

# --- 5. KANARYA: bilinen arka uç portu KRİTİK olarak işaretlenmeli ---
# 6379 (Redis) BACKEND_PORTS listesinde; sınıflandırma çalışmalı.
BACKEND_CANARY=6379
if ss -tlnH 2>/dev/null | grep -qE "(0\.0\.0\.0|\*):${BACKEND_CANARY}\b"; then
  ok "6379 zaten dinleniyor, bu test atlandı"
else
  python3 - "$BACKEND_CANARY" <<'PY' &
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.listen(1)
time.sleep(12)
PY
  bpid=$!
  sleep 2
  if ss -tlnH 2>/dev/null | grep -qE "(0\.0\.0\.0|\*):${BACKEND_CANARY}\b"; then
    out=$(ALLOW_PUBLIC="$all_ports" "$SCRIPT" 2>&1)
    grep -qE "KRİTİK +${BACKEND_CANARY}" <<<"$out"
    check "arka uç portu KRİTİK olarak sınıflandırıldı" 0 $?
  else
    bad "6379 kanaryası açılamadı"
  fi
  kill "$bpid" 2>/dev/null
  wait "$bpid" 2>/dev/null
fi

# --- 6. İzin listesi tam eşleşme olmalı (2 portu 22'yi affetmemeli) ---
out=$(ALLOW_PUBLIC="2" "$SCRIPT" 2>&1)
if grep -qE '(^|[^0-9])22($|[^0-9])' <<<"$all_ports"; then
  grep -qE "BULGU +22\b|KRİTİK +22\b" <<<"$out"
  check "kısmi eşleşme portu affetmiyor (2 != 22)" 0 $?
else
  ok "22 dinlenmiyor, bu test atlandı"
fi

echo
echo "geçen: $pass, kalan: $fail"
[ "$fail" -eq 0 ] || exit 1
