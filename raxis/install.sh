#!/usr/bin/env sh
# RAXIS Homebrew bootstrap helper.
#
# This script is intentionally POSIX sh, not bash or zsh. It is safe to run
# from zsh, bash, or via `sh install.sh`, and it avoids zsh's `read -p`
# coprocess trap.

set -eu

START_SERVICE=1
SKIP_PROVIDER=0
BREW_UPDATE=1
ADMIN=1
DATA_DIR=""
DATA_DIR_EXPLICIT=0
INSTALL_DIR=""
ENVIRONMENT="${RAXIS_ENV:-default}"
OPERATOR_KEY="${HOME:-}/raxis-keys/operator_private.pem"
OPERATOR_NAME="${USER:-operator}"

usage() {
    cat <<'EOF'
RAXIS Homebrew bootstrap

Usage:
  install.sh [options]

Options:
  --env <name>             Environment label. Default: default
                           Non-default labels use $(brew --prefix)/var/lib/raxis-<name>
                           unless --data-dir is also provided.
  --data-dir <path>        Data dir to initialize. Default: $(brew --prefix)/var/lib/raxis
  --install-dir <path>     Runtime bundle. Default: $(brew --prefix raxis)/share/raxis
  --operator-key <path>    Operator Ed25519 private key path. Default: ~/raxis-keys/operator_private.pem
  --operator-name <name>   Display name in the genesis operator cert. Default: $USER
  --no-admin              Do not grant dashboard-admin trust-root authority
  --skip-provider         Do not prompt/write the Anthropic provider credential
  --no-start-service      Do not start/restart brew services at the end
  --no-brew-update        Skip brew update
  -h, --help              Show this help

Environment:
  RAXIS_ANTHROPIC_API_KEY or ANTHROPIC_API_KEY may provide the provider key
  non-interactively. Otherwise the script prompts without echoing input.
EOF
}

log() {
    printf '%s\n' "==> $*"
}

warn() {
    printf '%s\n' "warning: $*" >&2
}

die() {
    printf '%s\n' "error: $*" >&2
    exit 1
}

service_running() {
    brew services list | awk '$1=="raxis" && $2=="started" { found=1 } END { exit found ? 0 : 1 }'
}

kickstart_launchd_service() {
    [ "$(uname -s)" = "Darwin" ] || return 1
    command -v launchctl >/dev/null 2>&1 || return 1
    launchctl kickstart -kp "gui/$(id -u)/homebrew.mxcl.raxis" >/dev/null 2>&1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --data-dir)
            [ "$#" -ge 2 ] || die "--data-dir requires a value"
            DATA_DIR="$2"
            DATA_DIR_EXPLICIT=1
            shift 2
            ;;
        --env|--environment)
            [ "$#" -ge 2 ] || die "--env requires a value"
            ENVIRONMENT="$2"
            shift 2
            ;;
        --install-dir)
            [ "$#" -ge 2 ] || die "--install-dir requires a value"
            INSTALL_DIR="$2"
            shift 2
            ;;
        --operator-key)
            [ "$#" -ge 2 ] || die "--operator-key requires a value"
            OPERATOR_KEY="$2"
            shift 2
            ;;
        --operator-name)
            [ "$#" -ge 2 ] || die "--operator-name requires a value"
            OPERATOR_NAME="$2"
            shift 2
            ;;
        --no-admin)
            ADMIN=0
            shift
            ;;
        --skip-provider)
            SKIP_PROVIDER=1
            shift
            ;;
        --no-start-service)
            START_SERVICE=0
            shift
            ;;
        --no-brew-update)
            BREW_UPDATE=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

command -v brew >/dev/null 2>&1 || die "Homebrew is required: https://brew.sh"

case "$ENVIRONMENT" in
    ""|*[!A-Za-z0-9_.-]*)
        die "environment must contain only letters, digits, dot, underscore, or dash"
        ;;
esac

if [ "$BREW_UPDATE" -eq 1 ]; then
    log "Updating Homebrew metadata"
    brew update
fi

log "Installing or upgrading RAXIS"
brew tap chika5105/raxis >/dev/null
if brew list --formula raxis >/dev/null 2>&1; then
    brew upgrade raxis
else
    brew install raxis
fi

if [ -z "$DATA_DIR" ]; then
    DATA_DIR="$(brew --prefix)/var/lib/raxis"
    if [ "$ENVIRONMENT" != "default" ] && [ "$DATA_DIR_EXPLICIT" -eq 0 ]; then
        DATA_DIR="$(brew --prefix)/var/lib/raxis-$ENVIRONMENT"
    fi
fi
if [ -z "$INSTALL_DIR" ]; then
    INSTALL_DIR="$(brew --prefix raxis)/share/raxis"
fi

export RAXIS_DATA_DIR="$DATA_DIR"
export RAXIS_ENV="$ENVIRONMENT"
export RAXIS_INSTALL_DIR="$INSTALL_DIR"
export RAXIS_OPERATOR_KEY="$OPERATOR_KEY"

log "Using RAXIS_INSTALL_DIR=$RAXIS_INSTALL_DIR"
log "Using RAXIS_DATA_DIR=$RAXIS_DATA_DIR"
log "Using RAXIS_ENV=$RAXIS_ENV"
log "Using RAXIS_OPERATOR_KEY=$RAXIS_OPERATOR_KEY"

find_openssl3() {
    if [ -n "${OPENSSL:-}" ] && [ -x "$OPENSSL" ]; then
        printf '%s\n' "$OPENSSL"
        return 0
    fi
    if command -v openssl >/dev/null 2>&1; then
        tmp="${TMPDIR:-/tmp}/raxis-openssl-check.$$"
        if openssl genpkey -algorithm ED25519 -out "$tmp" >/dev/null 2>&1; then
            rm -f "$tmp"
            command -v openssl
            return 0
        fi
        rm -f "$tmp"
    fi
    brew install openssl@3 >/dev/null
    candidate="$(brew --prefix openssl@3)/bin/openssl"
    [ -x "$candidate" ] || die "could not find Homebrew openssl@3 at $candidate"
    printf '%s\n' "$candidate"
}

if [ ! -f "$OPERATOR_KEY" ]; then
    log "Generating operator key"
    install -d -m 700 "$(dirname "$OPERATOR_KEY")"
    OPENSSL_BIN="$(find_openssl3)"
    "$OPENSSL_BIN" genpkey -algorithm ED25519 -out "$OPERATOR_KEY"
else
    log "Reusing existing operator key"
fi
chmod 600 "$OPERATOR_KEY"

initialized=0
if [ -f "$DATA_DIR/policy/policy.toml" ] && [ -f "$DATA_DIR/kernel.db" ]; then
    initialized=1
fi

if [ "$initialized" -eq 0 ]; then
    if [ -d "$DATA_DIR" ]; then
        if [ -f "$DATA_DIR/policy/policy.toml" ] ||
           [ -f "$DATA_DIR/kernel.db" ] ||
           [ -f "$DATA_DIR/keys/authority_keypair.pem" ]; then
            die "$DATA_DIR looks partially initialized. Inspect it manually before continuing."
        fi
        log "Removing uninitialized service skeleton at $DATA_DIR"
        brew services stop raxis >/dev/null 2>&1 || true
        rm -rf "$DATA_DIR"
    fi

    log "Running genesis"
    if [ "$ADMIN" -eq 1 ]; then
        raxis genesis \
            --operator-key "$OPERATOR_KEY" \
            --operator-name "$OPERATOR_NAME" \
            --admin
    else
        raxis genesis \
            --operator-key "$OPERATOR_KEY" \
            --operator-name "$OPERATOR_NAME"
    fi
else
    log "Data dir is already initialized; skipping genesis"
fi

prompt_secret() {
    prompt="$1"
    [ -t 0 ] || return 1
    printf '%s' "$prompt" >&2
    old_stty="$(stty -g 2>/dev/null || true)"
    stty -echo 2>/dev/null || true
    IFS= read -r value
    if [ -n "$old_stty" ]; then
        stty "$old_stty" 2>/dev/null || true
    else
        stty echo 2>/dev/null || true
    fi
    printf '\n' >&2
    printf '%s' "$value"
}

toml_string_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

policy="$DATA_DIR/policy/policy.toml"
[ -f "$policy" ] || die "missing policy after genesis: $policy"

if ! grep -Eq '^[[:space:]]*static_dir[[:space:]]*=' "$policy"; then
    log "Pointing dashboard at the Homebrew static bundle"
    tmp="${policy}.tmp.$$"
    awk -v static_dir="$RAXIS_INSTALL_DIR/dashboard" '
        BEGIN { in_dashboard = 0; inserted = 0; saw_dashboard = 0 }
        /^[[:space:]]*\[dashboard\][[:space:]]*$/ {
            print
            in_dashboard = 1
            saw_dashboard = 1
            next
        }
        /^[[:space:]]*\[/ && in_dashboard && !inserted {
            print "static_dir   = \"" static_dir "\""
            inserted = 1
            in_dashboard = 0
        }
        { print }
        END {
            if (in_dashboard && !inserted) {
                print "static_dir   = \"" static_dir "\""
                inserted = 1
            }
            if (!saw_dashboard) {
                print ""
                print "[dashboard]"
                print "enabled      = true"
                print "bind_address = \"127.0.0.1\""
                print "bind_port    = 9820"
                print "jwt_ttl_secs = 86400"
                print "static_dir   = \"" static_dir "\""
            }
        }
    ' "$policy" > "$tmp"
    mv "$tmp" "$policy"
fi

if [ "$SKIP_PROVIDER" -eq 0 ]; then
    provider_key="${RAXIS_ANTHROPIC_API_KEY:-${ANTHROPIC_API_KEY:-}}"
    if [ -z "$provider_key" ]; then
        provider_key="$(prompt_secret "Anthropic API key: " || true)"
    fi
    [ -n "$provider_key" ] || die "Anthropic key is required unless you pass --skip-provider"

    log "Writing Anthropic provider credential"
    install -d -m 700 "$DATA_DIR/providers"
    old_umask="$(umask)"
    umask 077
    escaped_provider_key="$(toml_string_escape "$provider_key")"
    {
        printf 'api_key = "%s"\n' "$escaped_provider_key"
        printf 'auth_header = "x-api-key"\n'
        printf 'auth_prefix = ""\n'
    } > "$DATA_DIR/providers/anthropic-prod.toml"
    umask "$old_umask"
    chmod 600 "$DATA_DIR/providers/anthropic-prod.toml"
    unset provider_key
    unset escaped_provider_key

    if ! grep -Eq '^[[:space:]]*\[model_routing\][[:space:]]*$' "$policy"; then
        log "Adding model routing policy block"
        cat >> "$policy" <<EOF

[model_routing]
orchestrator_model = "claude-haiku-4-5"
executor_model     = "claude-haiku-4-5"
reviewer_model     = "claude-haiku-4-5"
EOF
    fi

    if ! grep -Eq '^[[:space:]]*provider_id[[:space:]]*=[[:space:]]*"anthropic-prod"' "$policy"; then
        log "Adding Anthropic provider policy block"
        cat >> "$policy" <<'EOF'

[[providers]]
provider_id              = "anthropic-prod"
kind                     = "Anthropic"
credentials_file         = "anthropic-prod.toml"
inference_timeout_ms     = 120000
data_fetch_timeout_ms    = 30000
max_response_bytes       = 16777216
pricing.input_tokens_per_dollar  = 200000
pricing.output_tokens_per_dollar = 50000
EOF
    fi
fi

log "Signing policy"
raxis policy sign "$policy" --key "$DATA_DIR/keys/authority_keypair.pem"

log "Verifying local preflight"
raxis doctor || true

if [ "$START_SERVICE" -eq 1 ]; then
    log "Starting Homebrew service"
    raxis-supervisor reset-circuit-breaker --data-dir "$DATA_DIR" --yes >/dev/null 2>&1 || true
    brew services restart raxis || brew services start raxis
    sleep 3
    if ! service_running; then
        warn "brew services loaded RAXIS but did not report it running; asking launchd to start it now"
        kickstart_launchd_service || true
        sleep 3
    fi
    brew services list | awk 'NR==1 || $1=="raxis"'
    raxis-supervisor status --data-dir "$DATA_DIR" || true
    raxis doctor || true
fi

cat <<EOF

RAXIS bootstrap complete.

Use these exports in future shells:
  export RAXIS_INSTALL_DIR="$RAXIS_INSTALL_DIR"
  export RAXIS_DATA_DIR="$RAXIS_DATA_DIR"
  export RAXIS_ENV="$RAXIS_ENV"
  export RAXIS_OPERATOR_KEY="$RAXIS_OPERATOR_KEY"

Dashboard:
  http://127.0.0.1:9820
EOF
