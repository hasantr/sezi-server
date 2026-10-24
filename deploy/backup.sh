#!/usr/bin/env bash
# deploy/backup.sh — ATOMİK yedek (canlı-cp'nin bozuk-WAL riskini önler).
#
# SORUN: `.wrangler/state` altında D1 + DO-SQLite + (açıksa) R2 = ÜÇ ayrı store,
# hepsi SQLite (WAL modu). Servis ÇALIŞIRKEN `cp -r` = yarı-yazılmış WAL yakalar =
# BOZUK/tutarsız yedek. (Fable-denetim riski #3.)
#
# ÇÖZÜM: relay'i kısa süre durdur → rsync (tutarlı snapshot) → tekrar başlat.
# Duruş birkaç saniye; gece penceresinde yapılır (timer). Bu duruş AYNI ZAMANDA
# wrangler-dev uzun-ömür belirsizliğine (Fable riski #5) karşı GECE-RESTART görevi
# görür — iki ihtiyaç tek pencerede birleşir.
#
# Tarih damgası bash `date` ile üretilir (dış parametre gerekmez).
set -euo pipefail

STATE_DIR="${SEZI_STATE_DIR:-/var/lib/sezi/state}"
BACKUP_ROOT="${SEZI_BACKUP_DIR:-/var/lib/sezi/backups}"
KEEP="${SEZI_BACKUP_KEEP:-14}"          # kaç yedek saklanacak (gün ~= adet)
SERVICE="${SEZI_SERVICE:-sezi-relay}"

STAMP="$(date +%Y%m%d-%H%M%S)"
DEST="$BACKUP_ROOT/state-$STAMP"

mkdir -p "$BACKUP_ROOT"

if [ ! -d "$STATE_DIR" ]; then
	echo "[sezi-backup] HATA: state dizini yok: $STATE_DIR" >&2
	exit 1
fi

echo "[sezi-backup] $SERVICE durduruluyor (tutarlı snapshot için)…"
systemctl stop "$SERVICE"

# Servis durdu → WAL flush'landı → tüm SQLite dosyaları tutarlı. rsync tam kopya.
echo "[sezi-backup] rsync → $DEST"
rsync -a --delete "$STATE_DIR/" "$DEST/"

echo "[sezi-backup] $SERVICE tekrar başlatılıyor…"
systemctl start "$SERVICE"

# Eski yedekleri buda: en yeni KEEP adedi tut, gerisini sil.
echo "[sezi-backup] eski yedekler budanıyor (sakla=$KEEP)…"
ls -1dt "$BACKUP_ROOT"/state-* 2>/dev/null | tail -n +"$((KEEP + 1))" | while read -r old; do
	echo "[sezi-backup]   siliniyor: $old"
	rm -rf "$old"
done

echo "[sezi-backup] TAMAM → $DEST"
