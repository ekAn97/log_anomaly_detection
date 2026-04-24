# Red Flags
Backend for Red Flags Log Anomaly Detection System

## Installation & Usage

**Step 1**: Create Shared Infrastructure

```
docker network create log_ad_network
docker volume create log_ad_shared_logs
docker volume create log_ad_aggregated_logs
```

**Step 2**: Deploy the Backend

2.1 Clone repository
```
git clone https://github.com/SecureEU/red_flags_backend
cd red_flags_backend
```

2.2 Configure the environment
Create a .env file in the root of the **red_flags_backend** directory. Pay attention to the variables that require manual configuration.

```
cat > .env << 'EOF'
# ── PostgreSQL ────────────────────────────────────────────────────────
POSTGRES_USER=user123
POSTGRES_PASSWORD=your_secure_password_here        # ⚠ Change this
POSTGRES_DB=security_inc
POSTGRES_HOST=postgres                             # Internal — do not change
POSTGRES_PORT=5432

# ── FastAPI ───────────────────────────────────────────────────────────
API_HOST=0.0.0.0
API_PORT=8000

# ── Ollama (LLM) ──────────────────────────────────────────────────────
OLLAMA_HOST=detector-ollama                        # Internal — do not change
OLLAMA_PORT=11434
OLLAMA_MODEL=llama3.2:latest
OLLAMA_TIMEOUT=60
OLLAMA_TEMPERATURE=0.1

# ── Log Detector ──────────────────────────────────────────────────────
LOG_INPUT_PATH=/aggregated_logs                    # Internal — do not change
LOG_FILENAME=                                      # Leave empty — scans directory
DETECTION_THRESHOLD=0.85
POLL_INTERVAL=10                                   # Seconds between log scans
RATE_LIMIT_DELAY=1.0                               # Seconds between LLM calls

# ── Filebeat ──────────────────────────────────────────────────────────
SYSTEM_LOGS_ENABLED=true
SYSTEM_LOG_PATH=/logs/linux_logs.log               # Specify path if you process system logs
SYSTEM_SOURCE_HOST=log-generator
WEB_LOGS_ENABLED=false
WEB_LOG_PATH=/logs/web.log                         # Specify path if you process web logs
WEB_SOURCE_HOST=webserver
EOF
```

2.3 Build and start
First boot requires some time in order to pull and deploy the **llama3.2:latest** model (~2 GB). Detection begins right after Ollama and PostgreSQL db are both healthy containers.
```
docker compose up -d --build
```

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `log_detector` shows "Waiting for logs..." | `LOG_INPUT_PATH` incorrect | Ensure `LOG_INPUT_PATH=/aggregated_logs` in `.env`, then `docker compose stop log_detector && docker compose up -d log_detector` |
| `log_detector` exits on startup | PostgreSQL not ready | Wait for `incident_db` to show `(healthy)`, then `docker compose restart log_detector` |
| API not reachable | Port conflict or wrong `API_PORT` | Check `docker ps` for port mapping; verify `API_PORT=8000` in `.env` |
| Ollama container unhealthy | Model still downloading | Wait 5–10 minutes on first boot; monitor with `docker logs detector-ollama -f` |
| Frontend cannot reach API | Wrong `API_BASE_URL` | Must be `http://db-api:8000` (container name), not `localhost` |
| Frontend shows blank/error page | Wrong `APP_URL` | Set `APP_URL` to the actual server IP in the frontend `.env` |

### Monitor startup progress
```
# Watch Ollama pull the model
docker logs detector-ollama -f

# Once Ollama is ready, watch the detector
docker logs log_detector -f
```
Expected Outcome:
```
✓ Ollama ready with llama3.2:latest
Connected to PostgreSQL: security_inc
Found log file: aggregated-YYYYMMDD-N.ndjson
Processing: aggregated-YYYYMMDD-N.ndjson
```

Verify all backend containers are running
```
docker ps --format "table {{.Names}}\t{{.Status}}"
```
Expected outcome:
```
NAMES               STATUS
incident_db         Up X minutes (healthy)
test-filebeat       Up X minutes
detector-ollama     Up X minutes (healthy)
log_detector        Up X minutes
db-api              Up X minutes
```

Verify the API is responding: open http://<server_ip>:<API_PORT>/docs

### Stopping the system and reseting
```
cd ~/red_flags_backend && docker compose down
```

To fully reset and remove data
```
docker copmpose down -v
```


      
