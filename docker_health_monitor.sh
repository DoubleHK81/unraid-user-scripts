#!/bin/bash
#
# Unraid Docker Health Monitor
# Run via User Scripts plugin — schedule: every 15 minutes (custom cron)
# Checks for unhealthy/exited containers and sends Discord alerts
#
# TEST MODE: Run with --test to send a test Discord message
# REPORT MODE: Run with --report to list all container statuses
#

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  CONFIGURATION — Edit these values                                  ║
# ╚══════════════════════════════════════════════════════════════════════╝

# Discord Webhook URL — paste yours here (same webhook as process monitor, or a different one)
DISCORD_WEBHOOK="https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN"

# Notification settings
DISCORD_USERNAME="Docker Monitor"
SERVER_NAME=$(hostname)

# Log paths
LOG_DIR="/boot/logs"
LOG_FILE="${LOG_DIR}/docker_health.log"
MAX_LOG_SIZE=5242880  # 5MB — rotate if exceeded

# Cooldown: don't re-alert for the same container within this many minutes
COOLDOWN_MINUTES=60
COOLDOWN_FILE="${LOG_DIR}/.docker_health_cooldown"

# ─── CPU/Memory alert settings ──────────────────────────────────────────
CPU_ALERT_THRESHOLD=95           # Alert if container CPU exceeds this %
MEM_ALERT_THRESHOLD=90           # Alert if container MEM exceeds this %

# Containers to EXCLUDE from CPU/MEM alerts (these are expected to spike)
CPU_ALERT_EXCLUDE=(
    "jellyfin"
    "plex"
    "tdarr"
    "trailarr"
    "immich"
    "ollama"
    "open-webui"
)

# ─── Auto-restart settings ──────────────────────────────────────────────
AUTO_RESTART_ENABLED=false        # Set to true to enable auto-restart
MAX_RESTART_ATTEMPTS=3           # Max times to auto-restart a container per cooldown window
RESTART_TRACKER="${LOG_DIR}/.docker_restart_tracker"

# Containers to NEVER auto-restart (add container names here)
# These will still be alerted on but won't be touched
NEVER_RESTART=(
    # "pihole"
    # "mariadb"
)

# Only auto-restart these containers (leave empty to allow all)
# If populated, ONLY containers in this list will be auto-restarted
ONLY_RESTART=(
    # "plex"
    # "jellyfin"
)

# ─── Quick test mode ────────────────────────────────────────────────────
if [[ "$1" == "--test" ]]; then
    echo "Testing Discord webhook..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Content-Type: application/json" \
        -d "{\"content\":\"🐳 Test from ${SERVER_NAME} — Docker Health Monitor is working!\"}" \
        "$DISCORD_WEBHOOK")

    if [[ "$HTTP_CODE" == "204" || "$HTTP_CODE" == "200" ]]; then
        echo "SUCCESS (HTTP $HTTP_CODE) — Check your Discord channel!"
    else
        echo "FAILED (HTTP $HTTP_CODE)"
    fi
    exit 0
fi

# ─── Report mode ────────────────────────────────────────────────────────
if [[ "$1" == "--report" ]]; then
    echo "=== Docker Container Health Report ==="
    echo ""
    printf "%-30s %-15s %-15s %s\n" "CONTAINER" "STATUS" "HEALTH" "UPTIME"
    echo "────────────────────────────────────────────────────────────────────────"
    docker ps -a --format '{{.Names}}\t{{.Status}}' | while IFS=$'\t' read -r name status; do
        health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no check{{end}}' "$name" 2>/dev/null)
        state=$(docker inspect --format '{{.State.Status}}' "$name" 2>/dev/null)
        printf "%-30s %-15s %-15s %s\n" "$name" "$state" "$health" "$status"
    done
    echo ""
    echo "Totals:"
    echo "  Running:   $(docker ps -q | wc -l)"
    echo "  Stopped:   $(docker ps -a --filter 'status=exited' -q | wc -l)"
    echo "  Unhealthy: $(docker ps --filter 'health=unhealthy' -q | wc -l)"
    exit 0
fi

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  FUNCTIONS                                                          ║
# ╚══════════════════════════════════════════════════════════════════════╝

mkdir -p "$LOG_DIR"

# Rotate log if too large
if [[ -f "$LOG_FILE" ]] && [[ $(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt $MAX_LOG_SIZE ]]; then
    mv "$LOG_FILE" "${LOG_FILE}.old"
fi

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
EPOCH_NOW=$(date +%s)

log() { echo "[$TIMESTAMP] $1" >> "$LOG_FILE"; }

# ─── Cooldown check ────────────────────────────────────────────────────
is_on_cooldown() {
    local container="$1"
    if [[ ! -f "$COOLDOWN_FILE" ]]; then
        return 1  # No cooldown file, not on cooldown
    fi
    local last_alert=$(grep "^${container}=" "$COOLDOWN_FILE" 2>/dev/null | cut -d'=' -f2)
    if [[ -n "$last_alert" ]]; then
        local diff=$(( EPOCH_NOW - last_alert ))
        local cooldown_secs=$(( COOLDOWN_MINUTES * 60 ))
        if [[ "$diff" -lt "$cooldown_secs" ]]; then
            return 0  # On cooldown
        fi
    fi
    return 1  # Not on cooldown
}

set_cooldown() {
    local container="$1"
    # Remove old entry and add new one
    if [[ -f "$COOLDOWN_FILE" ]]; then
        grep -v "^${container}=" "$COOLDOWN_FILE" > "${COOLDOWN_FILE}.tmp" 2>/dev/null
        mv "${COOLDOWN_FILE}.tmp" "$COOLDOWN_FILE"
    fi
    echo "${container}=${EPOCH_NOW}" >> "$COOLDOWN_FILE"
    # Clean up entries older than 24 hours
    local cutoff=$(( EPOCH_NOW - 86400 ))
    if [[ -f "$COOLDOWN_FILE" ]]; then
        awk -F'=' -v cutoff="$cutoff" '$2+0 >= cutoff' "$COOLDOWN_FILE" > "${COOLDOWN_FILE}.tmp" 2>/dev/null
        mv "${COOLDOWN_FILE}.tmp" "$COOLDOWN_FILE"
    fi
}

# ─── Auto-restart helpers ───────────────────────────────────────────────
can_auto_restart() {
    local container="$1"

    # Check if auto-restart is enabled globally
    if [[ "$AUTO_RESTART_ENABLED" != true ]]; then
        return 1
    fi

    # Check NEVER_RESTART list
    for skip in "${NEVER_RESTART[@]}"; do
        if [[ "$container" == "$skip" ]]; then
            log "  (auto-restart blocked: $container is in NEVER_RESTART list)"
            return 1
        fi
    done

    # Check ONLY_RESTART list (if populated, container must be in it)
    if [[ ${#ONLY_RESTART[@]} -gt 0 ]]; then
        local found=false
        for allow in "${ONLY_RESTART[@]}"; do
            if [[ "$container" == "$allow" ]]; then
                found=true; break
            fi
        done
        if [[ "$found" == false ]]; then
            log "  (auto-restart blocked: $container is not in ONLY_RESTART list)"
            return 1
        fi
    fi

    # Check restart attempt count
    local attempts=0
    if [[ -f "$RESTART_TRACKER" ]]; then
        attempts=$(grep "^${container}=" "$RESTART_TRACKER" 2>/dev/null | cut -d'=' -f2 | cut -d'|' -f1)
        local last_time=$(grep "^${container}=" "$RESTART_TRACKER" 2>/dev/null | cut -d'|' -f2)
        attempts=${attempts:-0}
        last_time=${last_time:-0}

        # Reset counter if cooldown has passed
        local cooldown_secs=$(( COOLDOWN_MINUTES * 60 ))
        if [[ $(( EPOCH_NOW - last_time )) -gt $cooldown_secs ]]; then
            attempts=0
        fi
    fi

    if [[ "$attempts" -ge "$MAX_RESTART_ATTEMPTS" ]]; then
        log "  (auto-restart blocked: $container hit max attempts — $MAX_RESTART_ATTEMPTS)"
        return 1
    fi

    return 0
}

do_auto_restart() {
    local container="$1"
    local action="$2"  # "restart" or "start"

    log "  AUTO-RESTART: ${action}ing $container..."

    if [[ "$action" == "restart" ]]; then
        docker restart "$container" >> "$LOG_FILE" 2>&1
    else
        docker start "$container" >> "$LOG_FILE" 2>&1
    fi

    local result=$?
    if [[ $result -eq 0 ]]; then
        log "  AUTO-RESTART: $container ${action}ed successfully."
    else
        log "  AUTO-RESTART: Failed to ${action} $container (exit code: $result)"
    fi

    # Track the attempt
    if [[ -f "$RESTART_TRACKER" ]]; then
        grep -v "^${container}=" "$RESTART_TRACKER" > "${RESTART_TRACKER}.tmp" 2>/dev/null
        mv "${RESTART_TRACKER}.tmp" "$RESTART_TRACKER"
    fi
    local prev_attempts=0
    # Re-read in case it was reset
    prev_attempts=$(grep "^${container}=" "$RESTART_TRACKER" 2>/dev/null | cut -d'=' -f2 | cut -d'|' -f1)
    prev_attempts=${prev_attempts:-0}
    echo "${container}=$(( prev_attempts + 1 ))|${EPOCH_NOW}" >> "$RESTART_TRACKER"

    # Clean tracker entries older than 24 hours
    local cutoff=$(( EPOCH_NOW - 86400 ))
    if [[ -f "$RESTART_TRACKER" ]]; then
        awk -F'|' -v cutoff="$cutoff" '$2+0 >= cutoff' "$RESTART_TRACKER" > "${RESTART_TRACKER}.tmp" 2>/dev/null
        mv "${RESTART_TRACKER}.tmp" "$RESTART_TRACKER"
    fi

    return $result
}

# ─── Discord notification ───────────────────────────────────────────────
send_discord() {
    local color="$1"
    local title="$2"
    local description="$3"

    # Sanitize for JSON
    title=$(printf '%s' "$title" | tr -d '"' | tr '\n\r\t' '   ' | head -c 200)
    description=$(printf '%s' "$description" | tr -d '"' | head -c 1900)

    local ts
    ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    local running_count=$(docker ps -q 2>/dev/null | wc -l)
    local stopped_count=$(docker ps -a --filter 'status=exited' -q 2>/dev/null | wc -l)
    local unhealthy_count=$(docker ps --filter 'health=unhealthy' -q 2>/dev/null | wc -l)
    local total_count=$(docker ps -a -q 2>/dev/null | wc -l)

    local tmpfile="/tmp/docker_health_payload_$$.json"

    cat > "$tmpfile" <<EOF
{"username":"${DISCORD_USERNAME}","embeds":[{"title":"${title}","description":"${description}","color":${color},"fields":[{"name":"🟢 Running","value":"${running_count}","inline":true},{"name":"🔴 Stopped","value":"${stopped_count}","inline":true},{"name":"🟡 Unhealthy","value":"${unhealthy_count}","inline":true},{"name":"📦 Total","value":"${total_count}","inline":true}],"footer":{"text":"${SERVER_NAME} • Docker Health Monitor"},"timestamp":"${ts}"}]}
EOF

    local http_code
    http_code=$(curl -s -o /tmp/docker_health_response_$$.txt -w "%{http_code}" \
        -H "Content-Type: application/json" \
        --data-binary @"$tmpfile" \
        "$DISCORD_WEBHOOK" 2>&1)

    if [[ "$http_code" == "204" || "$http_code" == "200" ]]; then
        log "Discord notification sent (HTTP $http_code)."
    else
        log "Discord notification failed (HTTP $http_code)."
        log "Response: $(cat /tmp/docker_health_response_$$.txt 2>/dev/null)"
    fi

    rm -f "$tmpfile" "/tmp/docker_health_response_$$.txt"
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  HEALTH CHECKS                                                      ║
# ╚══════════════════════════════════════════════════════════════════════╝

log "===== Docker Health Check Started ====="

ALERT_MESSAGES=()
ALERT_COUNT=0

# ─── 1. Unhealthy containers ───────────────────────────────────────────
log "[CHECK] Unhealthy containers"
while IFS= read -r container; do
    [[ -z "$container" ]] && continue

    # Get health details
    health_log=$(docker inspect --format '{{if .State.Health}}{{range $i, $e := .State.Health.Log}}{{if eq $i 0}}{{$e.Output}}{{end}}{{end}}{{end}}' "$container" 2>/dev/null | head -c 200)
    uptime=$(docker ps --filter "name=^${container}$" --format '{{.Status}}' 2>/dev/null)

    log "  UNHEALTHY: $container — $uptime"

    # Attempt auto-restart
    local restarted=""
    if can_auto_restart "$container"; then
        do_auto_restart "$container" "restart"
        if [[ $? -eq 0 ]]; then
            restarted=" → auto-restarted ✅"
        else
            restarted=" → auto-restart failed ❌"
        fi
    fi

    if ! is_on_cooldown "$container"; then
        ALERT_MESSAGES+=("🟡 **${container}** is unhealthy — ${uptime}${restarted}")
        set_cooldown "$container"
        ((ALERT_COUNT++))
    else
        log "  (on cooldown, skipping alert for $container)"
    fi
done < <(docker ps --filter "health=unhealthy" --format '{{.Names}}' 2>/dev/null)

# ─── 2. Unexpectedly exited containers ─────────────────────────────────
log "[CHECK] Exited containers"
while IFS= read -r container; do
    [[ -z "$container" ]] && continue

    # Check restart policy — only alert for containers that should be running
    policy=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$container" 2>/dev/null)
    exit_code=$(docker inspect --format '{{.State.ExitCode}}' "$container" 2>/dev/null)
    finished=$(docker inspect --format '{{.State.FinishedAt}}' "$container" 2>/dev/null)

    # Skip containers with no restart policy (intentionally stopped)
    if [[ "$policy" == "no" || "$policy" == "" ]]; then
        log "  Exited (no restart policy, skipping): $container"
        continue
    fi

    log "  EXITED: $container — exit code: $exit_code, policy: $policy"

    # Attempt auto-restart
    local restarted=""
    if can_auto_restart "$container"; then
        do_auto_restart "$container" "start"
        if [[ $? -eq 0 ]]; then
            restarted=" → auto-started ✅"
        else
            restarted=" → auto-start failed ❌"
        fi
    fi

    if ! is_on_cooldown "$container"; then
        ALERT_MESSAGES+=("🔴 **${container}** has stopped (exit code: ${exit_code})${restarted}")
        set_cooldown "$container"
        ((ALERT_COUNT++))
    else
        log "  (on cooldown, skipping alert for $container)"
    fi
done < <(docker ps -a --filter "status=exited" --format '{{.Names}}' 2>/dev/null)

# ─── 3. Containers restarting in a loop ─────────────────────────────────
log "[CHECK] Restart loops"
while IFS= read -r container; do
    [[ -z "$container" ]] && continue
    restart_count=$(docker inspect --format '{{.RestartCount}}' "$container" 2>/dev/null)

    if [[ "$restart_count" -gt 5 ]]; then
        log "  RESTART LOOP: $container — restarted $restart_count times"

        if ! is_on_cooldown "loop_${container}"; then
            ALERT_MESSAGES+=("🔄 **${container}** is stuck in a restart loop (${restart_count} restarts)")
            set_cooldown "loop_${container}"
            ((ALERT_COUNT++))
        fi
    fi
done < <(docker ps -a --format '{{.Names}}' 2>/dev/null)

# ─── 4. High resource containers (optional) ────────────────────────────
log "[CHECK] Container resource usage"
STATS_OUTPUT=$(docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemPerc}}' 2>/dev/null || true)
if [[ -n "$STATS_OUTPUT" ]]; then
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        name=$(echo "$line" | awk '{print $1}')
        cpu=$(echo "$line" | awk '{print $2}' | tr -d '%')
        mem=$(echo "$line" | awk '{print $3}' | tr -d '%')

        # Convert to integer for comparison (avoids bc dependency)
        cpu_int=${cpu%.*}
        mem_int=${mem%.*}
        cpu_int=${cpu_int:-0}
        mem_int=${mem_int:-0}

        # Check if container is in the CPU exclusion list
        is_excluded=false
        for excluded in "${CPU_ALERT_EXCLUDE[@]}"; do
            if echo "$name" | grep -qi "$excluded"; then
                is_excluded=true; break
            fi
        done

        if [[ "$cpu_int" -gt "$CPU_ALERT_THRESHOLD" ]]; then
            if [[ "$is_excluded" == true ]]; then
                log "  HIGH CPU (excluded): $name at ${cpu}%"
            else
                log "  HIGH CPU: $name at ${cpu}%"
                if ! is_on_cooldown "cpu_${name}"; then
                    ALERT_MESSAGES+=("🔥 **${name}** is using ${cpu}% CPU")
                    set_cooldown "cpu_${name}"
                    ((ALERT_COUNT++))
                fi
            fi
        fi
        if [[ "$mem_int" -gt "$MEM_ALERT_THRESHOLD" ]]; then
            if [[ "$is_excluded" == true ]]; then
                log "  HIGH MEM (excluded): $name at ${mem}%"
            else
                log "  HIGH MEM: $name at ${mem}%"
                if ! is_on_cooldown "mem_${name}"; then
                    ALERT_MESSAGES+=("💾 **${name}** is using ${mem}% memory")
                    set_cooldown "mem_${name}"
                    ((ALERT_COUNT++))
                fi
            fi
        fi
    done <<< "$STATS_OUTPUT"
fi

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  SEND NOTIFICATIONS                                                  ║
# ╚══════════════════════════════════════════════════════════════════════╝

if [[ "$ALERT_COUNT" -gt 0 ]]; then
    log "CHECK COMPLETE: $ALERT_COUNT issue(s) found."

    # Build description
    DESC="**Found ${ALERT_COUNT} issue(s) with your Docker containers.**\\n\\n"
    for msg in "${ALERT_MESSAGES[@]}"; do
        clean_msg=$(printf '%s' "$msg" | tr -d '"' | tr -d '\\' | cut -c1-140)
        DESC+="• ${clean_msg}\\n"
    done
    DESC+="\\nCheck logs: \`${LOG_FILE}\`"

    send_discord 16744256 \
        "🐳 ${ALERT_COUNT} Docker issue(s) on ${SERVER_NAME}" \
        "$DESC"

    # Unraid notification
    if command -v /usr/local/emhttp/webGui/scripts/notify &>/dev/null; then
        /usr/local/emhttp/webGui/scripts/notify \
            -s "Docker Health Alert" \
            -d "$ALERT_COUNT Docker container issue(s) detected — check $LOG_FILE" \
            -i "warning"
    fi
else
    log "CHECK COMPLETE: All containers healthy."
fi

log "===== Docker Health Check Finished ====="
echo "" >> "$LOG_FILE"
