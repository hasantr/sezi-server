The Sezi relay on bare workerd (generated; see worker-rs/scripts/workerd_config.py).

Run, from this directory:
  workerd serve config.capnp --socket-addr=http=<ip>:<port> -dcache:storage=<state>/v3/cache -dd1:storage=<state>/v3/d1 -ddo:storage=<state>/v3/do -dkv:storage=<state>/v3/kv -dr2:storage=<state>/v3/r2

Environment (all optional; a missing one is the relay's default): FCM_PROJECT_ID, FCM_SERVICE_ACCOUNT, PUSH_RELAY_URL, RESET_PASSWORD, SEZI_CLAIM_SECRET, SEZI_TRUSTED_PROXY_HEADER, SEZI_WEB_ORIGINS, TURN_API_TOKEN, TURN_KEY_ID, TURN_MONTHLY_CAP, TURN_USER_MONTHLY_CAP
Text bindings baked into the captured config and dropped: none
