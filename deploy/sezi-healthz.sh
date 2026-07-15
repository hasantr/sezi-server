#!/usr/bin/env bash
# deploy/sezi-healthz.sh — canlılık bekçisi (watchdog).
#
# `Restart=always` süreç ÖLÜRSE toparlar; ama wrangler-dev "asılı ama süreç canlı"
# (WS reload takıldı / event-loop kilitlendi) durumuna düşebilir → süreç var, HTTP
# yanıt YOK. Bu bekçi /healthz'i yoklar; 200 değilse relay'i yeniden başlatır.
#
# İÇ portu (8788, relay'in KENDİSİ) yokla — nginx/caddy değil. Amaç relay-canlılığı;
# proxy arızasını relay-restart ÇÖZMEZ, o yüzden zinciri değil relay'i test ederiz.
set -euo pipefail

URL="${SEZI_HEALTHZ_URL:-http://127.0.0.1:8788/healthz}"
SERVICE="${SEZI_SERVICE:-sezi-relay}"

code="$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 5 "$URL" 2>/dev/null || echo 000)"

if [ "$code" != "200" ]; then
	logger -t sezi-healthz "healthz=$code (beklenen 200) → $SERVICE yeniden başlatılıyor"
	systemctl restart "$SERVICE"
else
	# Sessiz başarı (log gürültüsü yapma).
	exit 0
fi
