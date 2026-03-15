#!/bin/bash
#
# Unraid Process Monitor Script
# Run via User Scripts plugin — schedule: every hour (custom cron)
# Logs suspicious processes and sends Discord alerts
#
# TEST MODE: Run with --test to send a test Discord message
#

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  CONFIGURATION — Edit these values                                  ║
# ╚══════════════════════════════════════════════════════════════════════╝

# Discord Webhook URL — paste yours here
DISCORD_WEBHOOK="https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN"

# Notification settings
DISCORD_ALERT_ONLY=true          # true = only send on alerts, false = send every scan
DISCORD_USERNAME="Unraid Monitor"
SERVER_NAME=$(hostname)

# ─── Quick test mode ────────────────────────────────────────────────────
if [[ "$1" == "--test" ]]; then
    echo "Testing Discord webhook..."
    echo "URL: ${DISCORD_WEBHOOK:0:60}..."

    HTTP_CODE=$(curl -s -o /tmp/discord_test_response.txt -w "%{http_code}" \
        -H "Content-Type: application/json" \
        -d "{\"content\":\"Test from ${SERVER_NAME} - Process Monitor is working!\"}" \
        "$DISCORD_WEBHOOK")

    echo "HTTP Response: $HTTP_CODE"
    if [[ "$HTTP_CODE" == "204" || "$HTTP_CODE" == "200" ]]; then
        echo "SUCCESS - Check your Discord channel!"
    else
        echo "FAILED - Discord response:"
        cat /tmp/discord_test_response.txt 2>/dev/null
        echo ""
        echo "Common issues:"
        echo "  - Webhook URL is wrong or expired"
        echo "  - Channel was deleted"
        echo "  - Bot permissions changed"
    fi
    rm -f /tmp/discord_test_response.txt
    exit 0
fi

# Log paths
LOG_DIR="/boot/logs"
LOG_FILE="${LOG_DIR}/process_monitor.log"
ALERT_LOG="${LOG_DIR}/process_alerts.log"
MAX_LOG_SIZE=5242880  # 5MB — rotate if exceeded

# Thresholds
CPU_THRESHOLD=80
MEM_THRESHOLD=80
OPEN_FILES_THRESHOLD=1000

# Known safe process patterns (add your Docker containers, VMs, etc.)
SAFE_PATTERNS=(
    # Unraid core
    "emhttp" "shfs" "docker" "containerd" "libvirt" "qemu"
    "nginx" "php-fpm" "rpc" "ssh" "rsyslog" "crond" "ntpd"
    "agetty" "login" "bash" "mdcheck" "md/raid" "unraid"
    # Container init/supervision systems
    "s6-svscan" "s6-supervise" "s6-ipcserverd" "s6-linux-init"
    "tini" "dumb-init"
    # Your Docker containers & services
    "tailscale" "caddy" "gotenberg" "jellyfin" "vaultwarden"
    "ollama" "paperless-gpt" "gluetun" "tsdproxyd" "plex"
    # Common system services
    "smbd" "winbindd" "wsdd2" "dhcpcd" "inetd" "acpid" "mcelog"
    "nscd" "apcupsd" "dnsmasq" "virtlockd" "virtlogd" "httpd"
    "PM2" "node" "python" "python3" "busybox" "Xvfb" "sleep"
    "inotifywait" "udevd" "php" "java" "grep" "tail" "awk"
    # Kernel/hardware threads
    "kworker" "kvm-pit" "irq/" "nv_queue" "nv_mem_pool" "nvidia"
    "UVM" "vidmem" "card0" "btrfs" "xfs" "zfs" "zvol" "arc_"
    "spl_" "dbu_evict" "dbuf_evict" "l2arc" "usb-storage" "hwrng"
    "wg-crypt" "bond0" "tls-strp" "md-" "mdrecoveryd"
)

# Suspicious process names (cryptominers, malware, etc.)
# NOTE: "watchdog" removed — QEMU uses -watchdog-action which triggers false positives
# These are extended regex patterns for grep -iE
SUSPECT_NAMES=(
    "xmrig" "minerd" "kdevtmpfsi" "kinsing"
    "[.]hidden" "ksoftirqd_" "bioset_"
    "cryptonight" "stratum[+]tcp" "pool[.]" "nicehash"
    "ld-linux-x86.*[.]so" "[.]network$" "perfcc" "dota3"
)

# Processes to ALWAYS flag even if in SAFE_PATTERNS
# Add any services here that should NEVER be running on your server
ALWAYS_SUSPICIOUS=(
    # Example: "cryptominer_service"
)

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  FUNCTIONS                                                          ║
# ╚══════════════════════════════════════════════════════════════════════╝

mkdir -p "$LOG_DIR"

# Rotate log if too large
if [[ -f "$LOG_FILE" ]] && [[ $(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt $MAX_LOG_SIZE ]]; then
    mv "$LOG_FILE" "${LOG_FILE}.old"
fi

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
ALERT_COUNT=0
ALERT_MESSAGES=()

log() { echo "[$TIMESTAMP] $1" >> "$LOG_FILE"; }

alert() {
    echo "[$TIMESTAMP] ⚠ ALERT: $1" | tee -a "$LOG_FILE" >> "$ALERT_LOG"
    ((ALERT_COUNT++))
    # Categorize and build a human-readable summary for Discord
    local raw_msg="${1}"
    local category="" friendly_msg=""

    if [[ "$raw_msg" == "High CPU:"* ]]; then
        local a_pid a_cpu a_cmd
        a_pid=$(echo "$raw_msg" | grep -oP 'PID=\K[0-9]+')
        a_cpu=$(echo "$raw_msg" | grep -oP 'CPU=\K[0-9.]+%')
        a_cmd=$(echo "$raw_msg" | grep -oP 'CMD=\K.*' | cut -c1-60 | xargs)
        friendly_msg="A process is eating ${a_cpu} CPU — ${a_cmd} (PID ${a_pid})"

    elif [[ "$raw_msg" == "High MEM:"* ]]; then
        local a_pid a_mem a_cmd
        a_pid=$(echo "$raw_msg" | grep -oP 'PID=\K[0-9]+')
        a_mem=$(echo "$raw_msg" | grep -oP 'MEM=\K[0-9.]+%')
        a_cmd=$(echo "$raw_msg" | grep -oP 'CMD=\K.*' | cut -c1-60 | xargs)
        friendly_msg="A process is using ${a_mem} memory — ${a_cmd} (PID ${a_pid})"

    elif [[ "$raw_msg" == "Suspicious process matched"* ]]; then
        local a_pattern
        a_pattern=$(echo "$raw_msg" | grep -oP "matched '\K[^']+")
        friendly_msg="Found a process matching known threat pattern: ${a_pattern}"

    elif [[ "$raw_msg" == "UNEXPECTED SERVICE"* ]]; then
        local a_svc
        a_svc=$(echo "$raw_msg" | grep -oP "SERVICE '\K[^']+")
        if echo "$raw_msg" | grep -q "listening"; then
            friendly_msg="Unexpected service '${a_svc}' is listening on the network"
        else
            friendly_msg="Unexpected service '${a_svc}' is running on this server"
        fi

    elif [[ "$raw_msg" == "Excessive zombies:"* ]]; then
        local a_count
        a_count=$(echo "$raw_msg" | grep -oP 'Excessive zombies: \K[0-9]+')
        friendly_msg="${a_count} zombie processes detected (something may be stuck)"

    elif [[ "$raw_msg" == "Suspicious path:"* ]]; then
        local a_pid a_user a_exe
        a_pid=$(echo "$raw_msg" | grep -oP 'PID=\K[0-9]+')
        a_user=$(echo "$raw_msg" | grep -oP 'USER=\K[^ ]+')
        a_exe=$(echo "$raw_msg" | grep -oP 'EXE=\K[^ ]+' | head -c 60)
        friendly_msg="Process running from unusual location — ${a_exe:-unknown} by ${a_user} (PID ${a_pid})"

    elif [[ "$raw_msg" == "Excessive open files:"* ]]; then
        local a_pid a_count a_cmd
        a_pid=$(echo "$raw_msg" | grep -oP 'PID=\K[0-9]+')
        a_count=$(echo "$raw_msg" | grep -oP 'COUNT=\K[0-9]+')
        a_cmd=$(echo "$raw_msg" | grep -oP 'CMD=\K.*' | cut -c1-60 | xargs)
        friendly_msg="Process has ${a_count} open files — ${a_cmd} (PID ${a_pid})"

    elif [[ "$raw_msg" == "Unusual listener"* ]]; then
        local a_port
        a_port=$(echo "$raw_msg" | grep -oP 'port \K[0-9]+')
        friendly_msg="Unknown service listening on port ${a_port}"

    else
        # Fallback: clean up raw message
        friendly_msg=$(printf '%s' "$raw_msg" | cut -c1-120 | tr -d '"' | tr -d '\\' | tr '\n\r\t' '   ' | tr -s ' ')
    fi

    ALERT_MESSAGES+=("$friendly_msg")
}

separator() { echo "──────────────────────────────────────────────────" >> "$LOG_FILE"; }

# ─── Discord notification function ──────────────────────────────────────
send_discord() {
    local color="$1"
    local title="$2"
    local description="$3"
    local fields="$4"  # pre-built JSON array string

    # Sanitize title/description for JSON
    title=$(printf '%s' "$title" | tr -d '"' | tr '\n\r\t' '   ' | head -c 200)
    description=$(printf '%s' "$description" | tr -d '"' | head -c 1900)

    local timestamp
    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    local tmpfile="/tmp/discord_payload_$$.json"

    cat > "$tmpfile" <<DISCORD_JSON
{"username":"${DISCORD_USERNAME}","embeds":[{"title":"${title}","description":"${description}","color":${color},"fields":${fields},"footer":{"text":"${SERVER_NAME} • Process Monitor"},"timestamp":"${timestamp}"}]}
DISCORD_JSON

    local http_code
    http_code=$(curl -s -o /tmp/discord_response_$$.txt -w "%{http_code}" \
        -H "Content-Type: application/json" \
        --data-binary @"$tmpfile" \
        "$DISCORD_WEBHOOK" 2>&1)

    if [[ "$http_code" == "204" || "$http_code" == "200" ]]; then
        log "Discord notification sent successfully (HTTP $http_code)."
    else
        log "Discord notification failed (HTTP $http_code)."
        log "Discord response: $(cat /tmp/discord_response_$$.txt 2>/dev/null)"
        log "Payload sent: $(cat "$tmpfile" 2>/dev/null | head -c 500)"
    fi

    rm -f "$tmpfile" "/tmp/discord_response_$$.txt"
}

# ─── Build human-friendly Discord message ───────────────────────────────
build_discord_alert() {
    # Group alerts by type for a clean summary
    local cpu_alerts=() mem_alerts=() threat_alerts=() service_alerts=()
    local zombie_alerts=() path_alerts=() files_alerts=() listener_alerts=() other_alerts=()

    for msg in "${ALERT_MESSAGES[@]}"; do
        case "$msg" in
            *"CPU"*)        cpu_alerts+=("$msg") ;;
            *"memory"*)     mem_alerts+=("$msg") ;;
            *"threat"*)     threat_alerts+=("$msg") ;;
            *"service"*)    service_alerts+=("$msg") ;;
            *"zombie"*)     zombie_alerts+=("$msg") ;;
            *"unusual location"*) path_alerts+=("$msg") ;;
            *"open files"*) files_alerts+=("$msg") ;;
            *"listening"*)  listener_alerts+=("$msg") ;;
            *)              other_alerts+=("$msg") ;;
        esac
    done

    # Build description as a readable narrative
    local desc="**Heads up — found ${ALERT_COUNT} issue(s) on your server.**\\n\\n"

    # High-priority alerts first (threats & unexpected services)
    if [[ ${#threat_alerts[@]} -gt 0 || ${#service_alerts[@]} -gt 0 ]]; then
        desc+="🚨 **Needs Attention**\\n"
        for m in "${threat_alerts[@]}" "${service_alerts[@]}"; do
            local clean_m
            clean_m=$(printf '%s' "$m" | tr -d '"' | tr -d '\\' | cut -c1-140)
            desc+="• ${clean_m}\\n"
        done
        desc+="\\n"
    fi

    # Resource hogs
    if [[ ${#cpu_alerts[@]} -gt 0 || ${#mem_alerts[@]} -gt 0 ]]; then
        desc+="📊 **Resource Usage**\\n"
        for m in "${cpu_alerts[@]}" "${mem_alerts[@]}"; do
            local clean_m
            clean_m=$(printf '%s' "$m" | tr -d '"' | tr -d '\\' | cut -c1-140)
            desc+="• ${clean_m}\\n"
        done
        desc+="\\n"
    fi

    # Suspicious paths (summarize if many)
    if [[ ${#path_alerts[@]} -gt 0 ]]; then
        if [[ ${#path_alerts[@]} -gt 3 ]]; then
            desc+="📁 **Unusual Locations** — ${#path_alerts[@]} processes running from unexpected paths\\n"
            for m in "${path_alerts[@]:0:3}"; do
                local clean_m
                clean_m=$(printf '%s' "$m" | tr -d '"' | tr -d '\\' | cut -c1-140)
                desc+="• ${clean_m}\\n"
            done
            desc+="• ...and $((${#path_alerts[@]} - 3)) more\\n"
        else
            desc+="📁 **Unusual Locations**\\n"
            for m in "${path_alerts[@]}"; do
                local clean_m
                clean_m=$(printf '%s' "$m" | tr -d '"' | tr -d '\\' | cut -c1-140)
                desc+="• ${clean_m}\\n"
            done
        fi
        desc+="\\n"
    fi

    # Everything else (zombies, open files, listeners)
    local misc=("${zombie_alerts[@]}" "${files_alerts[@]}" "${listener_alerts[@]}" "${other_alerts[@]}")
    if [[ ${#misc[@]} -gt 0 ]]; then
        desc+="ℹ️ **Other**\\n"
        for m in "${misc[@]}"; do
            local clean_m
            clean_m=$(printf '%s' "$m" | tr -d '"' | tr -d '\\' | cut -c1-140)
            desc+="• ${clean_m}\\n"
        done
        desc+="\\n"
    fi

    desc+="Check the log for full details: \`${ALERT_LOG}\`"

    printf '%s' "$desc"
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  SCAN CHECKS                                                       ║
# ╚══════════════════════════════════════════════════════════════════════╝

log "===== Process Monitor Scan Started ====="

# ─── 1. High CPU consumers ─────────────────────────────────────────────
log "[CHECK] High CPU usage (>${CPU_THRESHOLD}%)"
while IFS= read -r line; do
    pid=$(echo "$line" | awk '{print $1}')
    cpu=$(echo "$line" | awk '{print $2}')
    mem=$(echo "$line" | awk '{print $3}')
    cmd=$(echo "$line" | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}')

    # Skip the monitoring script's own processes
    [[ "$cmd" =~ ^(ps|awk|grep|sort) ]] && continue

    is_safe=false
    for pattern in "${SAFE_PATTERNS[@]}"; do
        if echo "$cmd" | grep -qi "$pattern"; then
            is_safe=true; break
        fi
    done

    if [[ "$is_safe" == false ]]; then
        alert "High CPU: PID=$pid CPU=${cpu}% MEM=${mem}% CMD=$cmd"
    else
        log "  High CPU (safe): PID=$pid CPU=${cpu}% CMD=$cmd"
    fi
done < <(ps aux --sort=-%cpu | awk -v thresh="$CPU_THRESHOLD" 'NR>1 && $3+0 >= thresh {print $2, $3, $4, $11}')

# ─── 2. High Memory consumers ──────────────────────────────────────────
log "[CHECK] High Memory usage (>${MEM_THRESHOLD}%)"
while IFS= read -r line; do
    pid=$(echo "$line" | awk '{print $1}')
    mem=$(echo "$line" | awk '{print $2}')
    cmd=$(echo "$line" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}')

    is_safe=false
    for pattern in "${SAFE_PATTERNS[@]}"; do
        if echo "$cmd" | grep -qi "$pattern"; then
            is_safe=true; break
        fi
    done

    if [[ "$is_safe" == false ]]; then
        alert "High MEM: PID=$pid MEM=${mem}% CMD=$cmd"
    else
        log "  High MEM (safe): PID=$pid MEM=${mem}% CMD=$cmd"
    fi
done < <(ps aux --sort=-%mem | awk -v thresh="$MEM_THRESHOLD" 'NR>1 && $4+0 >= thresh {print $2, $4, $11}')

# ─── 3. Known suspicious process names ─────────────────────────────────
log "[CHECK] Known malicious process names"
for suspect in "${SUSPECT_NAMES[@]}"; do
    matches=$(ps aux | grep -iE "$suspect" | grep -v grep | grep -v "watchdog-action")
    if [[ -n "$matches" ]]; then
        alert "Suspicious process matched '$suspect': $(echo "$matches" | head -c 300)"
    fi
done

# ─── 3b. Always-flag list (services you do NOT run) ────────────────────
log "[CHECK] Processes that should NOT be running"
for suspect in "${ALWAYS_SUSPICIOUS[@]}"; do
    matches=$(ps aux | grep -i "$suspect" | grep -v grep)
    if [[ -n "$matches" ]]; then
        alert "UNEXPECTED SERVICE '$suspect' found! $(echo "$matches" | head -c 300)"
    fi
    # Also check network listeners
    if command -v ss &>/dev/null; then
        listeners=$(ss -tlnp 2>/dev/null | grep -i "$suspect")
        if [[ -n "$listeners" ]]; then
            alert "UNEXPECTED SERVICE '$suspect' listening on network: $(echo "$listeners" | head -c 300)"
        fi
    fi
done

# ─── 4. Zombie processes ───────────────────────────────────────────────
ZOMBIE_THRESHOLD=50  # Only alert if zombie count is abnormally high
log "[CHECK] Zombie processes"
zombie_count=$(ps aux | awk '$8 ~ /Z/ {count++} END {print count+0}')
if [[ "$zombie_count" -gt "$ZOMBIE_THRESHOLD" ]]; then
    alert "Excessive zombies: $zombie_count (threshold: $ZOMBIE_THRESHOLD)"
    ps aux | awk '$8 ~ /Z/' | head -20 >> "$LOG_FILE"
else
    log "  Zombie count: $zombie_count (within normal range)"
fi

# ─── 5. Processes from suspicious paths (skip Docker containers) ───────
log "[CHECK] Processes running from suspicious paths"
while IFS= read -r pid; do
    [[ -d "/proc/$pid" ]] || continue
    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null) || continue
    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null) || true

    # Skip if exe is empty (kernel threads, overlay mounts)
    [[ -z "$exe" ]] && continue

    # Skip Docker container processes (they legitimately use /tmp paths)
    cgroup=$(cat "/proc/$pid/cgroup" 2>/dev/null)
    if echo "$cgroup" | grep -qiE '(docker|containerd|lxc|kubepods)'; then
        continue
    fi

    # Only flag host processes running from suspicious paths
    if echo "$exe $cmdline" | grep -qiE '(/tmp/|/dev/shm/|/var/tmp/|\.\.)'; then
        # Double-check against safe patterns
        is_safe=false
        for pattern in "${SAFE_PATTERNS[@]}"; do
            if echo "$exe $cmdline" | grep -qi "$pattern"; then
                is_safe=true; break
            fi
        done
        if [[ "$is_safe" == false ]]; then
            user=$(ps -o user= -p "$pid" 2>/dev/null)
            alert "Suspicious path: PID=$pid USER=$user EXE=$exe CMD=${cmdline:0:200}"
        fi
    fi
done < <(ls /proc | grep -E '^[0-9]+$')

# ─── 6. Excessive open file counts ─────────────────────────────────────
log "[CHECK] Processes with excessive open files (>${OPEN_FILES_THRESHOLD})"
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    [[ -d "/proc/$pid/fd" ]] || continue
    count=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
    if [[ "$count" -gt "$OPEN_FILES_THRESHOLD" ]]; then
        cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null) || true
        alert "Excessive open files: PID=$pid COUNT=$count CMD=${cmd:0:100}"
    fi
done

# ─── 7. Unusual network listeners ──────────────────────────────────────
log "[CHECK] Network listeners"
if command -v ss &>/dev/null; then
    while IFS= read -r line; do
        port=$(echo "$line" | awk '{print $4}' | grep -oE '[0-9]+$')
        pid_name=$(echo "$line" | grep -oP 'users:\(\("([^"]+)' | head -1)

        if [[ -n "$port" ]] && [[ "$port" -gt 32768 ]]; then
            # Always flag services that shouldn't be running
            for suspect in "${ALWAYS_SUSPICIOUS[@]}"; do
                if echo "$pid_name $line" | grep -qi "$suspect"; then
                    alert "UNEXPECTED SERVICE '$suspect' listening on port $port: $line"
                    continue 2
                fi
            done

            is_safe=false
            for pattern in "${SAFE_PATTERNS[@]}"; do
                if echo "$pid_name $line" | grep -qi "$pattern"; then
                    is_safe=true; break
                fi
            done
            if [[ "$is_safe" == false ]]; then
                alert "Unusual listener on port $port: $line"
            fi
        fi
    done < <(ss -tlnp 2>/dev/null | tail -n +2)
fi

# ─── 8. Non-system root processes ──────────────────────────────────────
log "[CHECK] Non-system root processes"
while IFS= read -r line; do
    pid=$(echo "$line" | awk '{print $2}')
    cmd=$(echo "$line" | awk '{print $11}')

    if [[ "$pid" -gt 1000 ]]; then
        is_safe=false
        for pattern in "${SAFE_PATTERNS[@]}"; do
            if echo "$cmd" | grep -qi "$pattern"; then
                is_safe=true; break
            fi
        done
        if [[ "$is_safe" == false ]] && [[ -n "$cmd" ]]; then
            log "  Root process: PID=$pid CMD=$cmd"
        fi
    fi
done < <(ps aux | awk '$1 == "root"')

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  SYSTEM SUMMARY & NOTIFICATIONS                                     ║
# ╚══════════════════════════════════════════════════════════════════════╝

# Gather system stats
LOAD_AVG=$(cat /proc/loadavg | awk '{print $1, $2, $3}')
MEM_INFO=$(free -h | awk '/^Mem:/ {printf "%s / %s", $3, $2}')
SWAP_INFO=$(free -h | awk '/^Swap:/ {printf "%s / %s", $3, $2}')
PROC_COUNT=$(ps aux | wc -l)
UPTIME_STR=$(uptime -p 2>/dev/null || echo "N/A")
DISK_ROOT=$(df -h / 2>/dev/null | awk 'NR==2 {printf "%s / %s (%s)", $3, $2, $5}')

separator
log "[SUMMARY] System Resource Snapshot"
log "  Load Average: $LOAD_AVG"
log "  Memory: $MEM_INFO"
log "  Swap: $SWAP_INFO"
log "  Process Count: $PROC_COUNT"
log "  Uptime: $UPTIME_STR"

separator

# ─── Send Discord notification ──────────────────────────────────────────
# Build system stats fields JSON (used for both alert and all-clear)
STATS_FIELDS="[{\"name\":\"⏱ Load\",\"value\":\"${LOAD_AVG}\",\"inline\":true},{\"name\":\"💾 Memory\",\"value\":\"${MEM_INFO}\",\"inline\":true},{\"name\":\"💿 Swap\",\"value\":\"${SWAP_INFO}\",\"inline\":true},{\"name\":\"⚙️ Processes\",\"value\":\"${PROC_COUNT}\",\"inline\":true},{\"name\":\"📀 Disk\",\"value\":\"${DISK_ROOT}\",\"inline\":true},{\"name\":\"🕐 Uptime\",\"value\":\"${UPTIME_STR}\",\"inline\":true}]"

if [[ "$ALERT_COUNT" -gt 0 ]]; then
    log "SCAN COMPLETE: $ALERT_COUNT alert(s) found! Review $ALERT_LOG"

    DISCORD_DESC=$(build_discord_alert)

    send_discord \
        16711680 \
        "⚠️ ${ALERT_COUNT} issue(s) found on ${SERVER_NAME}" \
        "${DISCORD_DESC}" \
        "${STATS_FIELDS}"

    # Unraid web UI notification
    if command -v /usr/local/emhttp/webGui/scripts/notify &>/dev/null; then
        /usr/local/emhttp/webGui/scripts/notify \
            -s "Process Monitor Alert" \
            -d "$ALERT_COUNT suspicious process(es) detected — check $ALERT_LOG" \
            -i "warning"
    fi

else
    log "SCAN COMPLETE: No suspicious activity detected."

    # Send all-clear if configured
    if [[ "$DISCORD_ALERT_ONLY" == false ]]; then
        send_discord \
            65280 \
            "✅ All clear on ${SERVER_NAME}" \
            "Scan finished — no suspicious processes found. Everything looks good." \
            "${STATS_FIELDS}"
    fi
fi

log "===== Process Monitor Scan Finished ====="
echo "" >> "$LOG_FILE"
