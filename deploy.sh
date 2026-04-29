#!/usr/bin/env bash
# =============================================================================
# Homelab Dashboard — Deployment Script
# Usage: ./deploy.sh [user@host]
#
# Idempotent: safe to re-run. Preserves existing .env on re-deploy.
# First run: triggers interactive setup wizard to generate .env.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE=".env"
# REMOTE_DIR resolved after SSH connection (uses remote $HOME, no sudo needed)
# Override with DEPLOY_DIR env var if desired

# Default service ports — individual vars for bash 3.2/macOS compatibility.
# F-028: dropped DEFAULT_OPENVAS_HTTP_PORT — the OpenVAS :9392 mapping is no
# longer published from compose (the dashboard talks to gvmd on 9390 over
# the docker network instead), so there's nothing on the host to deconflict.
DEFAULT_FRONTEND_PORT=8080
DEFAULT_BACKEND_PORT=8000
DEFAULT_NPM_HTTP_PORT=80
DEFAULT_NPM_HTTPS_PORT=443
DEFAULT_NPM_ADMIN_PORT=8181

PORT_VARS="FRONTEND_PORT BACKEND_PORT NPM_HTTP_PORT NPM_HTTPS_PORT NPM_ADMIN_PORT"

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET} $*"; }
success() { echo -e "${GREEN}[OK]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }

# ─── Preflight ───────────────────────────────────────────────────────────────
command -v rsync  >/dev/null 2>&1 || error "rsync not found. Install it: brew install rsync / apt install rsync"
command -v ssh    >/dev/null 2>&1 || error "ssh not found."

# ─── Parse target host ───────────────────────────────────────────────────────
# Accept: positional arg, DEPLOY_HOST/DEPLOY_USER env vars, or interactive prompt
TARGET_HOST="${1:-}"
if [[ -z "$TARGET_HOST" && -n "${DEPLOY_HOST:-}" ]]; then
  TARGET_HOST="${DEPLOY_USER:-ubuntu}@${DEPLOY_HOST}"
fi
if [[ -z "$TARGET_HOST" ]]; then
  read -rp "$(echo -e "${CYAN}Target host${RESET} (user@ip or DEPLOY_USER@DEPLOY_HOST): ")" TARGET_HOST
fi
[[ -z "$TARGET_HOST" ]] && error "No target host provided. Pass as argument: ./deploy.sh user@host  or set DEPLOY_HOST and DEPLOY_USER env vars."

TARGET_IP="$(echo "$TARGET_HOST" | cut -d@ -f2)"

# ─── SSH ControlMaster — one password prompt for the whole deploy ─────────────
SSH_CTL_DIR="/tmp/hl-ssh"
mkdir -p "$SSH_CTL_DIR" && chmod 700 "$SSH_CTL_DIR"
SSH_CTL_PATH="$SSH_CTL_DIR/%r@%h"

SSH_CMD="ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=no \
  -o ControlMaster=auto \
  -o ControlPath=$SSH_CTL_PATH \
  -o ControlPersist=600"

# Trap ensures the master socket is closed even if the script exits early
trap 'ssh -O exit -o ControlPath="$SSH_CTL_PATH" "$TARGET_HOST" 2>/dev/null || true' EXIT

info "Testing SSH connection to $TARGET_HOST..."
$SSH_CMD "$TARGET_HOST" 'echo "SSH OK"' || error "Cannot reach $TARGET_HOST via SSH."
success "SSH connection established."

# ─── Resolve remote deploy directory (no sudo needed) ────────────────────────
REMOTE_HOME=$($SSH_CMD "$TARGET_HOST" 'echo $HOME')
REMOTE_DIR="${DEPLOY_DIR:-${REMOTE_HOME}/homelab-dashboard}"
info "Deploy directory: $REMOTE_DIR"

# ─── Remote prerequisites check ──────────────────────────────────────────────
info "Checking remote prerequisites..."
$SSH_CMD "$TARGET_HOST" bash <<'PREREQ'
  errors=0
  docker version > /dev/null 2>&1 || { echo "  [MISSING] docker"; errors=$((errors+1)); }
  docker compose version > /dev/null 2>&1 || { echo "  [MISSING] docker compose plugin"; errors=$((errors+1)); }
  docker ps > /dev/null 2>&1 || { echo "  [MISSING] docker access — run: sudo usermod -aG docker $USER  then log out and back in"; errors=$((errors+1)); }
  [[ $errors -gt 0 ]] && { echo "See: https://docs.docker.com/engine/install/ubuntu/"; exit 1; }
  echo "  Docker OK"
PREREQ
success "Remote prerequisites satisfied."

# ─── Check for existing .env on remote ───────────────────────────────────────
HAVE_REMOTE_ENV=false
if $SSH_CMD "$TARGET_HOST" "test -f $REMOTE_DIR/$ENV_FILE" 2>/dev/null; then
  info "Found existing .env on remote — downloading to preserve settings..."
  scp -q -o "ControlPath=$SSH_CTL_PATH" "$TARGET_HOST:$REMOTE_DIR/$ENV_FILE" "$SCRIPT_DIR/$ENV_FILE"
  HAVE_REMOTE_ENV=true
  success ".env downloaded."
fi

# ─── First-run wizard ────────────────────────────────────────────────────────
if [[ "$HAVE_REMOTE_ENV" == "false" ]]; then
  info "No existing configuration found — running first-time setup wizard..."
  source "$SCRIPT_DIR/setup-wizard.sh"
  run_setup_wizard
fi

# ─── Port deconfliction ───────────────────────────────────────────────────────
info "Checking for port conflicts on $TARGET_HOST..."

OCCUPIED_PORTS=$($SSH_CMD "$TARGET_HOST" bash <<'EOPORTS'
  # Docker-allocated ports
  docker_ports=$(docker ps --format '{{.Ports}}' 2>/dev/null \
    | grep -oE '[0-9]+(->[0-9]+)?' | grep -oE '^[0-9]+' || true)
  # System-level listening ports (ss preferred, netstat fallback)
  sys_ports=$(ss -tlnH 2>/dev/null | awk '{print $4}' | grep -oE '[0-9]+$' \
    || netstat -tlnp 2>/dev/null | awk '/LISTEN/{print $4}' | grep -oE '[0-9]+$' \
    || true)
  printf '%s\n%s\n' "$docker_ports" "$sys_ports" | grep -E '^[0-9]+$' | sort -nu
EOPORTS
)

ASSIGNED_PORTS=""

find_free_port() {
  local port=$1
  while printf '%s\n%s\n' "$OCCUPIED_PORTS" "$ASSIGNED_PORTS" | grep -q "^${port}$"; do
    port=$((port + 1))
  done
  ASSIGNED_PORTS="${ASSIGNED_PORTS}${port}"$'\n'
  echo "$port"
}

# Initialise .env from example if still missing
if [[ ! -f "$SCRIPT_DIR/$ENV_FILE" ]]; then
  cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/$ENV_FILE"
fi

# ─── Reconcile DOCKER_GID with remote host ───────────────────────────────────
# The backend container's non-root user needs a supplementary group matching
# the GID that owns /var/run/docker.sock on the HOST — otherwise the OpenVAS
# reset/rotate flow can't talk to dockerd (EACCES). That GID varies by distro:
# 999 on Debian/Ubuntu, 988 on RHEL/Fedora, other values on rootless/podman.
# Hardcoding the Debian default in .env.example used to leave RHEL/Fedora
# users with a silently broken rotate path. Detect it for real.
info "Detecting host's docker group GID..."
REMOTE_DOCKER_GID=$($SSH_CMD "$TARGET_HOST" "stat -c '%g' /var/run/docker.sock 2>/dev/null" || echo "")
if [[ -z "$REMOTE_DOCKER_GID" || ! "$REMOTE_DOCKER_GID" =~ ^[0-9]+$ ]]; then
  warn "Could not read /var/run/docker.sock GID on remote — leaving DOCKER_GID untouched. OpenVAS rotate may fail."
else
  if grep -q "^DOCKER_GID=" "$SCRIPT_DIR/$ENV_FILE" 2>/dev/null; then
    CURRENT_DOCKER_GID=$(grep "^DOCKER_GID=" "$SCRIPT_DIR/$ENV_FILE" | cut -d= -f2)
    if [[ "$CURRENT_DOCKER_GID" != "$REMOTE_DOCKER_GID" ]]; then
      info "DOCKER_GID drift: .env has ${CURRENT_DOCKER_GID}, host socket is ${REMOTE_DOCKER_GID} — updating."
      sed -i.bak "s/^DOCKER_GID=.*/DOCKER_GID=${REMOTE_DOCKER_GID}/" "$SCRIPT_DIR/$ENV_FILE"
    else
      success "DOCKER_GID=${REMOTE_DOCKER_GID} matches host."
    fi
  else
    echo "DOCKER_GID=${REMOTE_DOCKER_GID}" >> "$SCRIPT_DIR/$ENV_FILE"
    info "Assigned DOCKER_GID=${REMOTE_DOCKER_GID}"
  fi
fi

for VAR in $PORT_VARS; do
  DEFAULT_VAR="DEFAULT_${VAR}"
  DEFAULT="${!DEFAULT_VAR}"
  if grep -q "^${VAR}=" "$SCRIPT_DIR/$ENV_FILE" 2>/dev/null; then
    CURRENT=$(grep "^${VAR}=" "$SCRIPT_DIR/$ENV_FILE" | cut -d= -f2)
    # If current port is externally occupied OR already claimed by an earlier VAR, reassign
    if printf '%s\n%s\n' "$OCCUPIED_PORTS" "$ASSIGNED_PORTS" | grep -q "^${CURRENT}$"; then
      FREE=$(find_free_port "$DEFAULT")
      warn "Port $CURRENT ($VAR) is occupied — reassigning to $FREE"
      sed -i.bak "s/^${VAR}=.*/${VAR}=${FREE}/" "$SCRIPT_DIR/$ENV_FILE"
    else
      ASSIGNED_PORTS="${ASSIGNED_PORTS}${CURRENT}"$'\n'
    fi
  else
    FREE=$(find_free_port "$DEFAULT")
    echo "${VAR}=${FREE}" >> "$SCRIPT_DIR/$ENV_FILE"
    info "Assigned ${VAR}=${FREE}"
  fi
done

# Read final port assignments for the summary (fall back to defaults if not set)
FRONTEND_PORT=$(grep "^FRONTEND_PORT=" "$SCRIPT_DIR/$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_FRONTEND_PORT")
BACKEND_PORT=$(grep "^BACKEND_PORT="  "$SCRIPT_DIR/$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_BACKEND_PORT")
NPM_ADMIN_PORT=$(grep "^NPM_ADMIN_PORT=" "$SCRIPT_DIR/$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_NPM_ADMIN_PORT")
FRONTEND_PORT="${FRONTEND_PORT:-$DEFAULT_FRONTEND_PORT}"
BACKEND_PORT="${BACKEND_PORT:-$DEFAULT_BACKEND_PORT}"
NPM_ADMIN_PORT="${NPM_ADMIN_PORT:-$DEFAULT_NPM_ADMIN_PORT}"

# ─── Refresh frontend lockfile ───────────────────────────────────────────────
# `npm ci` inside the container refuses to install if package-lock.json is out
# of sync with package.json. Update the lockfile here — this is a no-op when
# already in sync and takes ~1s. --package-lock-only avoids writing node_modules
# (which is gitignored + rsync-excluded anyway).
if [[ -f "$SCRIPT_DIR/frontend/package.json" ]]; then
  if command -v npm >/dev/null 2>&1; then
    info "Refreshing frontend/package-lock.json to match package.json..."
    ( cd "$SCRIPT_DIR/frontend" && \
      npm install --package-lock-only --ignore-scripts --no-audit --no-fund \
        >/dev/null 2>&1 ) \
      && success "Lockfile in sync." \
      || warn "npm install --package-lock-only failed — container build may fail on 'npm ci'. Run it manually: (cd frontend && npm install)"
  else
    warn "npm not found on host — skipping lockfile refresh. If package.json changed, container 'npm ci' will fail."
  fi
fi

# ─── Sync files to remote ────────────────────────────────────────────────────
info "Syncing project files to $TARGET_HOST:$REMOTE_DIR ..."
$SSH_CMD "$TARGET_HOST" "mkdir -p $REMOTE_DIR/data"

rsync -az --delete \
  -e "ssh -o ControlMaster=no -o ControlPath=$SSH_CTL_PATH" \
  --exclude='.git' \
  --exclude='node_modules' \
  --exclude='frontend/dist' \
  --exclude='frontend/.vite' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='.env.bak' \
  --exclude='data/' \
  --exclude='.venv/' \
  "$SCRIPT_DIR/" \
  "$TARGET_HOST:$REMOTE_DIR/"

success "Files synced."

# ─── Determine active compose profiles ───────────────────────────────────────
CERT_TYPE=$(grep "^CERT_TYPE=" "$SCRIPT_DIR/$ENV_FILE" | cut -d= -f2 | tr -d '"' || echo "none")
PROFILES="--profile openvas"
[[ "$CERT_TYPE" != "none" ]] && PROFILES="--profile proxy $PROFILES"

# ─── Deploy on remote ────────────────────────────────────────────────────────
info "Deploying on $TARGET_HOST (this may take a few minutes on first run)..."

$SSH_CMD "$TARGET_HOST" bash << REMOTE
  set -euo pipefail
  cd "$REMOTE_DIR"

  # Stop and remove any existing containers to clear stale port bindings
  echo "  Stopping existing containers..."
  docker compose $PROFILES down --remove-orphans 2>/dev/null || true

  # Nuclear cleanup: force-remove any lingering homelab-* containers and prune networks
  docker ps -aq --filter "name=homelab-" 2>/dev/null | xargs -r docker rm -f 2>/dev/null || true
  docker network prune -f 2>/dev/null || true

  # ── homelab-data volume migration ─────────────────────────────────────
  # The backend image now runs as non-root (uid/gid 1000). An existing
  # homelab-data volume from the old image was populated as root, so the
  # backend gets EACCES on /data until we chown it. Fire a one-shot
  # busybox container to do the chown in-place — idempotent (no-op if
  # already correct), non-destructive (just ownership, data untouched).
  if docker volume inspect homelab-dashboard_homelab-data >/dev/null 2>&1; then
    echo "  Reconciling /data ownership for non-root backend..."
    # F-026: pinned to match docker-compose.yml's data-init sidecar.
    # Both run the same chown, both are tiny one-shots — pinning
    # avoids the supply-chain footgun of pulling whatever the latest
    # busybox happens to be on each deploy.
    docker run --rm \
      -v homelab-dashboard_homelab-data:/data \
      busybox:1.37 \
      chown -R 1000:1000 /data 2>/dev/null || \
      echo "  (chown failed — backend entrypoint will retry at startup)"
  fi

  # Pull upstream images quietly (ignore pull errors for local-only images)
  echo "  Pulling images..."
  docker compose $PROFILES pull --quiet 2>/dev/null || true

  # Build and start containers fresh
  echo "  Building and starting containers..."
  docker compose $PROFILES up -d --build

  echo ""
  echo "  Containers:"
  docker compose $PROFILES ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
REMOTE

# ─── Wait for backend health ─────────────────────────────────────────────────
info "Waiting for backend to become healthy..."

HEALTH_URL="http://${TARGET_IP}:${BACKEND_PORT}/health"
# Container healthcheck has start_period=60s + 5 retries @ 15s; allow outer
# waiter to exceed that so first-run deploys don't report a false failure.
MAX_WAIT=180
WAITED=0
until curl -sf "$HEALTH_URL" > /dev/null 2>&1 || [[ $WAITED -ge $MAX_WAIT ]]; do
  sleep 2
  WAITED=$((WAITED + 2))
  echo -ne "  ${CYAN}...${RESET} ${WAITED}s\r"
done

if curl -sf "$HEALTH_URL" > /dev/null 2>&1; then
  success "Backend healthy at $HEALTH_URL"
else
  warn "Backend did not respond within ${MAX_WAIT}s — check logs: ssh $TARGET_HOST 'docker logs homelab-backend'"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
success "Deployment complete!"
echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Homelab Dashboard${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════${RESET}"
echo -e "  Dashboard    ${GREEN}http://${TARGET_IP}:${FRONTEND_PORT}${RESET}"
echo -e "  API          ${GREEN}http://${TARGET_IP}:${BACKEND_PORT}${RESET}"
[[ "$CERT_TYPE" != "none" ]] && \
echo -e "  NGINX Proxy  ${GREEN}http://${TARGET_IP}:${NPM_ADMIN_PORT}${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${YELLOW}First visit will open the setup wizard.${RESET}"
echo -e "  ${CYAN}Logs:${RESET} ssh $TARGET_HOST 'cd $REMOTE_DIR && docker compose logs -f'"
echo ""
