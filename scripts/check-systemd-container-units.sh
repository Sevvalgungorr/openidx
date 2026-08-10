#!/usr/bin/env bash
#
# check-systemd-container-units.sh — reboot'ta ayağa kalkmayacak unit'leri bulur.
#
# `podman generate systemd` şu biçimi üretir:
#
#     Type=forking
#     PIDFile=/run/.../overlay-containers/<CONTAINER-ID>/userdata/conmon.pid
#     ExecStart=/usr/bin/podman start <name>
#
# `<CONTAINER-ID>` container **yeniden yaratıldığında değişir**. Unit dosyası
# eski ID'yi göstermeye devam eder, systemd conmon PID'ini bulamaz ve servisi
# `failed` sayar. Container elle çalıştığı sürece her şey normal görünür;
# sorun ancak **makine yeniden başlatıldığında** ortaya çıkar ve o an servis
# gelmez.
#
# Bu betik, bir güvenlik düzeltmesi için container'ı recreate etmenin sessizce
# "reboot'ta gelmeyen servis" ürettiği gerçek bir olaydan sonra yazıldı.
#
# Kullanım:
#   scripts/check-systemd-container-units.sh
#
# Çıkış kodu: bayat PIDFile içeren unit varsa 1, yoksa 0.

set -uo pipefail

UNIT_DIR="${UNIT_DIR:-$HOME/.config/systemd/user}"

if [ ! -d "$UNIT_DIR" ]; then
  echo "SKIP: unit dizini yok: $UNIT_DIR"
  exit 0
fi

if ! command -v podman >/dev/null 2>&1; then
  echo "SKIP: podman yok, container ID'leri doğrulanamaz."
  exit 0
fi

shopt -s nullglob
units=("$UNIT_DIR"/container-*.service)
shopt -u nullglob

if [ ${#units[@]} -eq 0 ]; then
  echo "container-*.service unit'i yok."
  exit 0
fi

stale=0
missing=0
checked=0

for f in "${units[@]}"; do
  base=$(basename "$f" .service)
  name=${base#container-}

  pidfile_id=$(grep -oE 'overlay-containers/[a-f0-9]{64}' "$f" 2>/dev/null \
               | head -1 | cut -d/ -f2)

  # PIDFile yoksa unit zaten ID'den bağımsızdır (Type=simple biçimi).
  [ -n "$pidfile_id" ] || continue

  checked=$((checked + 1))
  current_id=$(podman inspect "$name" --format '{{.Id}}' 2>/dev/null)

  if [ -z "$current_id" ]; then
    missing=$((missing + 1))
    printf 'YOK     %-28s unit var ama container yok\n' "$name"
  elif [ "$pidfile_id" != "$current_id" ]; then
    stale=$((stale + 1))
    printf 'BAYAT   %-28s PIDFile=%s… container=%s…\n' \
      "$name" "${pidfile_id:0:12}" "${current_id:0:12}"
  fi
done

echo
if [ "$checked" -eq 0 ]; then
  echo "SONUÇ: PIDFile kullanan unit yok, hepsi ID'den bağımsız."
  exit 0
fi

if [ "$stale" -eq 0 ] && [ "$missing" -eq 0 ]; then
  echo "SONUÇ: $checked unit denetlendi, hepsi güncel container'ı gösteriyor."
  exit 0
fi

echo "SONUÇ: $stale bayat, $missing eksik ($checked denetlendi)."
echo
echo "Düzeltme — unit'i container ID'sinden bağımsız yap:"
echo "  1. PIDFile satırını sil"
echo "  2. Type=forking  ->  Type=simple"
echo "  3. ExecStart=... podman start <ad>  ->  podman start --attach <ad>"
echo "  4. systemctl --user daemon-reload && systemctl --user restart <unit>"
echo
echo "Doğrulama: 'systemctl --user is-active <unit>' active dönmeli."
exit 1
