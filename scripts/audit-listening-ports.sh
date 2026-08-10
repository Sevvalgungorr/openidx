#!/usr/bin/env bash
#
# audit-listening-ports.sh — hangi servisler tüm arayüzlerde dinliyor?
#
# Amaç: bir OpenIDX host'unda "yalnızca loopback olması gereken" bir
# servisin sessizce 0.0.0.0'a bağlanmasını yakalamak.
#
# Bu, ağ firewall'ının yerini tutmaz. Host üzerinde çalışan bir süreç
# firewall'ı zaten atlar; bu betik "açık bırakılmış" olanı görünür kılar.
#
# Kullanım:
#   scripts/audit-listening-ports.sh              # rapor + çıkış kodu
#   scripts/audit-listening-ports.sh --probe      # açık portlara auth testi de yap
#   ALLOW_PUBLIC="22 443" scripts/audit-listening-ports.sh
#
# Çıkış kodu: izin listesinde olmayan, tüm arayüzlerde dinleyen port
# varsa 1, yoksa 0.

set -uo pipefail

# Dışarıya açık olması BEKLENEN portlar. Bunun dışındaki her şey bulgudur.
# Ortam değişkeniyle geçersiz kılınabilir (site-özel değerler repoya girmez).
DEFAULT_ALLOW_PUBLIC="22 80 443 1280 3022 3023"
ALLOW_PUBLIC="${ALLOW_PUBLIC:-$DEFAULT_ALLOW_PUBLIC}"

# Asla tüm arayüzlerde dinlememesi gereken, bilinen arka uç servisleri.
# Burada eşleşme olursa bulgu "KRİTİK" olarak işaretlenir.
declare -A BACKEND_PORTS=(
  [2379]="etcd (client)"
  [2380]="etcd (peer)"
  [5432]="PostgreSQL"
  [6379]="Redis"
  [56379]="Redis (OpenIDX)"
  [55432]="PostgreSQL (OpenIDX)"
  [7474]="Neo4j HTTP"
  [7687]="Neo4j Bolt"
  [9180]="APISIX admin API"
  [9280]="APISIX admin API"
  [9090]="APISIX control API"
  [9098]="APISIX control API"
  [11211]="memcached"
  [27017]="MongoDB"
  [9200]="Elasticsearch"
)

PROBE=0
[[ "${1:-}" == "--probe" ]] && PROBE=1

# Bir portun kimlik doğrulama isteyip istemediğini kabaca yoklar.
# Yalnızca --probe ile çalışır ve sadece okuma yapar; hiçbir şey yazmaz.
probe_port() {
  local port="$1" host="${PROBE_HOST:-127.0.0.1}"

  if ! command -v curl >/dev/null 2>&1; then
    echo "        (probe atlandı: curl yok)"
    return
  fi

  local code
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 4 \
         "http://${host}:${port}/" 2>/dev/null)
  [[ "$code" == "000" ]] && code=$(curl -sk -o /dev/null -w '%{http_code}' \
         --max-time 4 "https://${host}:${port}/" 2>/dev/null)

  case "$code" in
    401|403) echo "        HTTP $code — kimlik doğrulama var" ;;
    000)     echo "        HTTP yanıtı yok (HTTP olmayan protokol olabilir)" ;;
    200)     echo "        HTTP 200 — kimlik doğrulamasız yanıt veriyor, İNCELE" ;;
    *)       echo "        HTTP $code" ;;
  esac
}

if ! command -v ss >/dev/null 2>&1; then
  echo "HATA: 'ss' bulunamadı (iproute2 gerekli)." >&2
  exit 2
fi

# Tüm arayüzlerde dinleyen TCP portları (0.0.0.0, *, [::]).
mapfile -t public_ports < <(
  ss -tlnH 2>/dev/null \
    | awk '{print $4}' \
    | grep -E '^(0\.0\.0\.0|\*|\[::\]):' \
    | grep -oE '[0-9]+$' \
    | sort -n -u
)

if [[ ${#public_ports[@]} -eq 0 ]]; then
  echo "Tüm arayüzlerde dinleyen TCP portu yok."
  exit 0
fi

findings=0
critical=0

echo "Tüm arayüzlerde dinleyen TCP portları: ${#public_ports[@]}"
echo "İzin listesi (ALLOW_PUBLIC): $ALLOW_PUBLIC"
echo

for port in "${public_ports[@]}"; do
  if grep -qw -- "$port" <<<"$ALLOW_PUBLIC"; then
    continue
  fi

  findings=$((findings + 1))
  label="${BACKEND_PORTS[$port]:-}"

  if [[ -n "$label" ]]; then
    critical=$((critical + 1))
    printf 'KRİTİK  %-6s %s — arka uç servisi tüm arayüzlerde dinliyor\n' "$port" "$label"
  else
    printf 'BULGU   %-6s (izin listesinde değil)\n' "$port"
  fi

  if [[ $PROBE -eq 1 ]]; then
    probe_port "$port"
  fi
done

echo
if [[ $findings -eq 0 ]]; then
  echo "SONUÇ: izin listesi dışında açık port yok."
  exit 0
fi

echo "SONUÇ: $findings bulgu ($critical kritik)."
echo
echo "Düzeltme sırası:"
echo "  1. Servis gerçekten uzaktan erişilmeli mi? Hayırsa loopback'e bağla."
echo "     Docker/Podman:  -p 127.0.0.1:<host>:<container>"
echo "     etcd:           --listen-client-urls=http://127.0.0.1:2379"
echo "     PostgreSQL:     listen_addresses = 'localhost'"
echo "     Redis:          bind 127.0.0.1"
echo "  2. Erişilmeli ise kimlik doğrulama + TLS ZORUNLU (bkz. docs/host-firewall-baseline.md)."
echo "  3. Ağ firewall'ı üçüncü katman; ilk ikisinin yerine geçmez."
exit 1
