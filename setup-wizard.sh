#!/usr/bin/env bash
# =============================================================================
# Homelab Dashboard — Setup Wizard
# Sourced by deploy.sh on first run to collect COMPOSE-TIME configuration.
#
# Scope note: this wizard only captures values that must be baked into .env
# before containers start (external hostname, domain mode, TLS cert strategy).
# All other integration credentials (UniFi, Elasticsearch, OpenVAS, Claude,
# per-device scan credentials) are collected at runtime in the in-app
# Settings page after first login — that way we don't ask the same question
# twice, and secrets are stored in config.yml rather than a shell env file.
# =============================================================================

_prompt() {
  local var_name="$1"
  local prompt_text="$2"
  local default="$3"
  local secret="${4:-false}"

  local display_default=""
  [[ -n "$default" ]] && display_default=" [${default}]"

  if [[ "$secret" == "true" ]]; then
    read -rsp "$(echo -e "\033[0;36m  ${prompt_text}${display_default}:\033[0m ") " value
    echo ""
  else
    read -rp "$(echo -e "\033[0;36m  ${prompt_text}${display_default}:\033[0m ") " value
  fi

  [[ -z "$value" ]] && value="$default"
  eval "${var_name}=\"${value}\""
}

run_setup_wizard() {
  local env_file="${SCRIPT_DIR}/.env"
  cp "${SCRIPT_DIR}/.env.example" "$env_file"

  echo ""
  echo -e "\033[1m\033[0;36m╔══════════════════════════════════════╗\033[0m"
  echo -e "\033[1m\033[0;36m║   Homelab Dashboard — First Run      ║\033[0m"
  echo -e "\033[1m\033[0;36m╚══════════════════════════════════════╝\033[0m"
  echo ""
  echo -e "  This wizard only collects values needed to bring the stack up."
  echo -e "  Integrations (UniFi, Elasticsearch, OpenVAS, Claude, scan"
  echo -e "  credentials) are configured from the in-app Settings page"
  echo -e "  after first login."
  echo ""

  # ── Network access ────────────────────────────────────────────────────────
  echo -e "\033[1m[1/2] Network Access\033[0m"
  _prompt EXTERNAL_HOST "Server LAN IP or hostname" "$(echo "$TARGET_HOST" | cut -d@ -f2)"

  echo "  Access mode:"
  echo "    1) Raw IP (no domain)"
  echo "    2) Local domain (e.g. homelab.local)"
  _prompt DOMAIN_CHOICE "Choose" "1"
  [[ "$DOMAIN_CHOICE" == "2" ]] && DOMAIN_MODE="domain" || DOMAIN_MODE="ip"

  # ── TLS / certificate strategy ────────────────────────────────────────────
  echo ""
  echo -e "\033[1m[2/2] TLS Certificate\033[0m"
  echo "  Certificate type:"
  echo "    1) None (HTTP only)"
  echo "    2) Self-signed HTTPS"
  echo "    3) Let's Encrypt (requires public domain)"
  _prompt CERT_CHOICE "Choose" "1"
  case "$CERT_CHOICE" in
    2) CERT_TYPE="selfsigned" ;;
    3) CERT_TYPE="letsencrypt"; _prompt LETSENCRYPT_EMAIL "Let's Encrypt email" "" ;;
    *) CERT_TYPE="none" ;;
  esac

  # ── Write .env ────────────────────────────────────────────────────────────
  {
    sed \
      -e "s|^EXTERNAL_HOST=.*|EXTERNAL_HOST=${EXTERNAL_HOST}|" \
      -e "s|^DOMAIN_MODE=.*|DOMAIN_MODE=${DOMAIN_MODE}|" \
      -e "s|^CERT_TYPE=.*|CERT_TYPE=${CERT_TYPE}|" \
      -e "s|^LETSENCRYPT_EMAIL=.*|LETSENCRYPT_EMAIL=${LETSENCRYPT_EMAIL:-}|" \
      "${SCRIPT_DIR}/.env.example"
  } > "$env_file"

  echo ""
  echo -e "\033[0;32m  Compose-time config saved to .env\033[0m"
  echo -e "  Open the dashboard after deploy completes to configure"
  echo -e "  integrations in Settings."
  echo ""
}
