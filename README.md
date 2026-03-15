# Unraid Monitoring Scripts

A collection of monitoring and security scripts for Unraid servers with Discord notifications.

## Scripts

### 1. Process Monitor (`process_monitor.sh`)
Scans for suspicious processes, malware, resource abuse, and unusual network activity.

**What it checks:**
- High CPU/Memory usage (configurable thresholds)
- Known malware/cryptominer process names
- Services that should never be running (customizable list)
- Excessive zombie processes
- Processes running from suspicious paths (`/tmp`, `/dev/shm`, etc.)
- Excessive open file descriptors
- Unusual network listeners on high ports
- Non-system root processes

**Schedule:** Every hour (`0 * * * *`)

### 2. Docker Health Monitor (`docker_health_monitor.sh`)
Monitors Docker container health and resource usage with optional auto-restart.

**What it checks:**
- Unhealthy containers (failed health checks)
- Unexpectedly exited containers
- Containers stuck in restart loops
- High CPU/Memory usage per container (with exclusion list)

**Features:**
- Configurable CPU/MEM alert exclusions for containers expected to spike (transcoding, ML, etc.)
- 1-hour cooldown per container to prevent alert spam
- Optional auto-restart with max attempt limits and allow/deny lists
- `--test` mode to verify Discord webhook
- `--report` mode for terminal-based container status overview

**Schedule:** Every 15 minutes (`*/15 * * * *`)

## Setup

### Prerequisites
- Unraid server with the **User Scripts** plugin installed
- A **Discord webhook URL** for notifications

### Installation

1. Clone this repo or download the scripts
2. Copy each script into a new User Script in Unraid:
   - Settings → User Scripts → Add New Script
3. Edit the configuration section at the top of each script:
   - Set your `DISCORD_WEBHOOK` URL
   - Adjust thresholds and safe patterns as needed
4. Set the schedule:
   - Process Monitor: `0 * * * *` (every hour)
   - Docker Health Monitor: `*/15 * * * *` (every 15 minutes)
5. Test each script:
   ```bash
   ./process_monitor.sh --test
   ./docker_health_monitor.sh --test
   ```

### Configuration

Both scripts use a **configuration section** at the top of the file. Key settings:

#### Process Monitor
| Setting | Default | Description |
|---------|---------|-------------|
| `DISCORD_WEBHOOK` | — | Your Discord webhook URL |
| `DISCORD_ALERT_ONLY` | `true` | Only send Discord messages when alerts are found |
| `CPU_THRESHOLD` | `80` | Alert when a process exceeds this CPU % |
| `MEM_THRESHOLD` | `80` | Alert when a process exceeds this MEM % |
| `OPEN_FILES_THRESHOLD` | `1000` | Alert when a process has more open files than this |
| `SAFE_PATTERNS` | *(see script)* | Known safe process patterns to suppress alerts |
| `SUSPECT_NAMES` | *(see script)* | Known malware/suspicious process patterns |
| `ALWAYS_SUSPICIOUS` | *(empty)* | Processes to always flag even if in safe patterns |

#### Docker Health Monitor
| Setting | Default | Description |
|---------|---------|-------------|
| `DISCORD_WEBHOOK` | — | Your Discord webhook URL |
| `COOLDOWN_MINUTES` | `60` | Don't re-alert for the same container within this window |
| `CPU_ALERT_THRESHOLD` | `95` | Alert when container CPU exceeds this % |
| `MEM_ALERT_THRESHOLD` | `90` | Alert when container MEM exceeds this % |
| `CPU_ALERT_EXCLUDE` | *(see script)* | Containers excluded from CPU/MEM alerts |
| `AUTO_RESTART_ENABLED` | `false` | Enable auto-restart of unhealthy/exited containers |
| `MAX_RESTART_ATTEMPTS` | `3` | Max auto-restart attempts per cooldown window |
| `NEVER_RESTART` | *(empty)* | Containers to never auto-restart |
| `ONLY_RESTART` | *(empty)* | If set, only these containers can be auto-restarted |

### Log Files

| Log | Path | Description |
|-----|------|-------------|
| Process Monitor | `/boot/logs/process_monitor.log` | Full scan history |
| Process Alerts | `/boot/logs/process_alerts.log` | Alerts only |
| Docker Health | `/boot/logs/docker_health.log` | Container health history |

Logs auto-rotate at 5MB.

## Discord Notifications

Both scripts send rich Discord embeds with categorized alerts and system stats.

**Process Monitor** sends alerts grouped by type: threats, resource usage, suspicious paths, and other issues — with a system snapshot (load, memory, swap, disk, uptime).

**Docker Health Monitor** sends alerts with container status summary (running, stopped, unhealthy, total counts).

## Security Note

**Never commit your Discord webhook URL to a public repository.** The scripts ship with a placeholder value. Set your real webhook URL only in the copies deployed on your server.

## License

MIT
