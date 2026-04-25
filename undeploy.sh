#!/usr/bin/env bash
# =============================================================================
# Homelab Dashboard — Undeployment Script
# Usage: ./undeploy.sh [user@host]
#
# Tears down the Homelab Dashboard stack on the target server:
#   - Stops and removes all `homelab-*` containers
#   - Removes the `homelab-dashboard` compose project's volumes (DESTROYS DATA)
#   - Removes the built frontend/backend images
#   - Deletes the remote deploy directory (code + config + local DB)
#
# Does NOT touch:
#   - Other Docker projects on the host
#   - System packages or user accounts
#   - Upstream pulled images (openvas, npm) unless --purge-images
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET} $*"; }
success() { echo -e "${GREEN}[OK]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }

# ─── Flags ───────────────────────────────────────────────────────────────────
PURGE_IMAGES=false
YES=false
for arg in "$@"; do
  case "$arg" in
    --purge-images) PURGE_IMAGES=true ;;
    --yes|-y)       YES=true ;;
    --help|-h)
      sed -n '2,17p' "$0"
      echo
      echo "Options:"
      echo "  --purge-images   Also remove upstream images (openvas, npm)"
      echo "  --yes | -y       Skip the confirmation prompt (destructive — use with care)"
      exit 0
      ;;
  esac
done

# ─── Preflight ───────────────────────────────────────────────────────────────
command -v ssh >/dev/null 2>&1 || error "ssh not found."

# ─── Parse target host (same resolution as deploy.sh) ────────────────────────
TARGET_HOST=""
for arg in "$@"; do
  case "$arg" in
    --*) ;;  # ignore flags
    *)   [[ -z "$TARGET_HOST" ]] && TARGET_HOST="$arg" ;;
  esac
done
if [[ -z "$TARGET_HOST" && -n "${DEPLOY_HOST:-}" ]]; then
  TARGET_HOST="${DEPLOY_USER:-ubuntu}@${DEPLOY_HOST}"
fi
if [[ -z "$TARGET_HOST" ]]; then
  read -rp "$(echo -e "${CYAN}Target host${RESET} (user@ip or DEPLOY_USER@DEPLOY_HOST): ")" TARGET_HOST
fi
[[ -z "$TARGET_HOST" ]] && error "No target host provided."

# ─── SSH ControlMaster ────────────────────────────────────────────────────────
SSH_CTL_DIR="/tmp/hl-ssh"
mkdir -p "$SSH_CTL_DIR" && chmod 700 "$SSH_CTL_DIR"
SSH_CTL_PATH="$SSH_CTL_DIR/%r@%h"

SSH_CMD="ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=no \
  -o ControlMaster=auto \
  -o ControlPath=$SSH_CTL_PATH \
  -o ControlPersist=600"

trap 'ssh -O exit -o ControlPath="$SSH_CTL_PATH" "$TARGET_HOST" 2>/dev/null || true' EXIT

info "Testing SSH connection to $TARGET_HOST..."
$SSH_CMD "$TARGET_HOST" 'echo "SSH OK"' >/dev/null || error "Cannot reach $TARGET_HOST via SSH."
success "SSH connection established."

# ─── Resolve remote deploy directory ─────────────────────────────────────────
REMOTE_HOME=$($SSH_CMD "$TARGET_HOST" 'echo $HOME')
REMOTE_DIR="${DEPLOY_DIR:-${REMOTE_HOME}/homelab-dashboard}"

# ─── Survey what's on the box ────────────────────────────────────────────────
info "Surveying remote state..."

SURVEY=$($SSH_CMD "$TARGET_HOST" bash <<REMOTE_SURVEY
  set +e
  echo "=== CONTAINERS ==="
  docker ps -a --filter "name=homelab-" --format "{{.Names}}  ({{.Status}})" 2>/dev/null
  echo
  echo "=== VOLUMES ==="
  docker volume ls --format "{{.Name}}" 2>/dev/null | grep -E "^homelab-dashboard_"
  echo
  echo "=== IMAGES ==="
  docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | grep -E "^homelab-dashboard-"
  echo
  echo "=== DIRECTORY ==="
  if [[ -d "$REMOTE_DIR" ]]; then
    du -sh "$REMOTE_DIR" 2>/dev/null | awk '{print \$1"  "\$2}'
  else
    echo "(not present)"
  fi
REMOTE_SURVEY
)

echo
echo -e "${BOLD}${YELLOW}══ WILL BE DESTROYED ══════════════════════════${RESET}"
echo "$SURVEY"
echo -e "${BOLD}${YELLOW}═══════════════════════════════════════════════${RESET}"
echo

# ─── Confirmation ────────────────────────────────────────────────────────────
if [[ "$YES" != "true" ]]; then
  echo -e "${RED}${BOLD}This is destructive.${RESET} All containers, volumes, and data above will be deleted."
  echo -e "Type ${BOLD}YES${RESET} (all caps) to proceed: "
  read -r CONFIRM
  [[ "$CONFIRM" == "YES" ]] || error "Aborted — nothing was changed."
fi

# ─── Teardown ────────────────────────────────────────────────────────────────
info "Tearing down Homelab Dashboard on $TARGET_HOST..."

$SSH_CMD "$TARGET_HOST" bash <<REMOTE_TEARDOWN
  set +e
  cd "$REMOTE_DIR" 2>/dev/null

  # 1. Compose-driven stop + volume removal. Try all profiles to catch
  #    optional services (proxy, openvas).
  if [[ -f "$REMOTE_DIR/docker-compose.yml" ]]; then
    echo "  Stopping compose project (including volumes)..."
    docker compose --profile proxy --profile openvas down --volumes --remove-orphans 2>/dev/null
    docker compose down --volumes --remove-orphans 2>/dev/null
  else
    echo "  No compose file on remote — falling back to container name matching."
  fi

  # 2. Force-remove any lingering homelab-* containers (belt-and-braces
  #    — handles stacks deployed from other dirs / old compose names).
  lingering=\$(docker ps -aq --filter "name=homelab-" 2>/dev/null)
  if [[ -n "\$lingering" ]]; then
    echo "  Removing lingering containers..."
    echo "\$lingering" | xargs -r docker rm -f 2>/dev/null
  fi

  # 3. Remove any volumes belonging to the homelab-dashboard project that
  #    the \`compose down -v\` above didn't catch (e.g. from renamed projects).
  stray_vols=\$(docker volume ls -q --filter "name=homelab-dashboard_" 2>/dev/null)
  if [[ -n "\$stray_vols" ]]; then
    echo "  Removing stray project volumes..."
    echo "\$stray_vols" | xargs -r docker volume rm -f 2>/dev/null
  fi

  # 4. Remove built frontend/backend images.
  built_imgs=\$(docker images -q --filter "reference=homelab-dashboard-*" 2>/dev/null)
  if [[ -n "\$built_imgs" ]]; then
    echo "  Removing built project images..."
    echo "\$built_imgs" | xargs -r docker rmi -f 2>/dev/null
  fi

  # 5. Optionally purge upstream images (opt-in because they're reusable).
  if [[ "$PURGE_IMAGES" == "true" ]]; then
    echo "  Purging upstream images (openvas, npm)..."
    docker rmi -f immauss/openvas:latest jc21/nginx-proxy-manager:latest 2>/dev/null
  fi

  # 6. Prune the compose-network (leftover bridge).
  docker network prune -f 2>/dev/null >/dev/null

  # 7. Remove the deploy directory.
  if [[ -d "$REMOTE_DIR" ]]; then
    echo "  Removing $REMOTE_DIR..."
    rm -rf "$REMOTE_DIR"
  fi

  echo "  Done."
REMOTE_TEARDOWN

# ─── Verify ──────────────────────────────────────────────────────────────────
info "Verifying teardown..."
REMAINING=$($SSH_CMD "$TARGET_HOST" bash <<'VERIFY'
  c=$(docker ps -a --filter "name=homelab-" -q 2>/dev/null | wc -l)
  v=$(docker volume ls -q --filter "name=homelab-dashboard_" 2>/dev/null | wc -l)
  i=$(docker images -q --filter "reference=homelab-dashboard-*" 2>/dev/null | wc -l)
  echo "containers=$c volumes=$v images=$i"
VERIFY
)

if [[ "$REMAINING" == "containers=0 volumes=0 images=0" ]]; then
  success "Undeployment complete — the Grid has been de-rezzed."
else
  warn "Teardown left residue: $REMAINING"
  warn "Inspect with: ssh $TARGET_HOST 'docker ps -a --filter name=homelab-; docker volume ls | grep homelab'"
fi

echo
echo -e "${CYAN}══════════════════════════════════════════════${RESET}"
echo -e "  Host            ${BOLD}${TARGET_HOST}${RESET}"
echo -e "  Deploy dir      ${REMOTE_DIR}  ${GREEN}(removed)${RESET}"
echo -e "  Purged images   ${PURGE_IMAGES}"
echo -e "${CYAN}══════════════════════════════════════════════${RESET}"
echo
