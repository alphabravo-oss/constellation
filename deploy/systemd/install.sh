#!/usr/bin/env bash
# Constellation systemd installer.
#
#   sudo bash install.sh              # interactive install, system-wide
#   sudo bash install.sh --from-source  # build binaries from this repo first
#   sudo bash install.sh --upgrade      # rebuild/replace binaries, keep env files
#   sudo bash install.sh --user         # systemd --user mode (no sudo, dev test path)
#   sudo bash install.sh --non-interactive --roles=api,scanner   # CI / scripted
#
# See deploy/systemd/README.md and docs/deployment-systemd.md for the long version.

set -euo pipefail

# --------------------------------------------------------------------------- vars

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

FROM_SOURCE=0
UPGRADE=0
USER_MODE=0
NON_INTERACTIVE=0
ROLES_ARG=""
DATABASE_URL_ARG=""
LISTEN_ADDR_ARG=""
PURGE=0
DOWNLOAD_VERSION="${CONSTELLATION_VERSION:-latest}"

# Output paths (overridden in --user mode).
SYSTEMD_DIR="/etc/systemd/system"
ETC_DIR="/etc/constellation"
LIB_DIR="/var/lib/constellation"
LOG_DIR="/var/log/constellation"
BIN_DIR="/usr/local/bin"
SVC_USER="constellation"
SVC_GROUP="constellation"
SYSTEMCTL="systemctl"

# Binaries we know how to build/install. Order matters for start ordering.
BINARIES=(
  constellation-api
  constellation-scanner
  constellation-operator
  constellation-runtime-agent
  constellation-discoverer
  audit-archiver
  constellationctl
)
# Plus scanner-driver, which lives under deploy/e2e/scanner-driver.
DRIVER_BIN="constellation-scanner-driver"

# Map role -> .service file basename.
declare -A ROLE_UNITS=(
  [api]=constellation-api.service
  [scanner]=constellation-scanner.service
  [operator]=constellation-operator.service
  [runtime-agent]=constellation-runtime-agent.service
  [discoverer]=constellation-discoverer.service
  [audit-archiver]=constellation-audit-archiver.service
  [scanner-driver]=constellation-scanner-driver.service
)
# Map role -> env-file basename.
declare -A ROLE_ENVS=(
  [api]=api.env
  [scanner]=scanner.env
  [operator]=operator.env
  [runtime-agent]=runtime-agent.env
  [discoverer]=discoverer.env
  [audit-archiver]=audit-archiver.env
  [scanner-driver]=scanner-driver.env
)

# --------------------------------------------------------------------------- color / log

if [[ -t 1 ]]; then
  C_BLD=$'\e[1m'; C_DIM=$'\e[2m'; C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_RST=$'\e[0m'
else
  C_BLD=""; C_DIM=""; C_RED=""; C_GRN=""; C_YEL=""; C_RST=""
fi
log()  { printf "%s==>%s %s\n" "$C_BLD" "$C_RST" "$*"; }
warn() { printf "%s!! %s%s\n" "$C_YEL" "$*" "$C_RST" >&2; }
fail() { printf "%s** %s%s\n" "$C_RED" "$*" "$C_RST" >&2; exit 1; }
ok()   { printf "%sok%s %s\n" "$C_GRN" "$C_RST" "$*"; }

# --------------------------------------------------------------------------- args

usage() {
  cat <<EOF
Constellation systemd installer.

Usage: $0 [options]

Options:
  --from-source           Build binaries from $REPO_ROOT (default: download release).
  --upgrade               Rebuild/replace binaries, keep env files in place.
  --user                  Install as systemd --user (no sudo). For dev/test only.
  --non-interactive       No prompts; requires --roles + --database-url.
  --roles=api,scanner,..  Comma-list of roles to enable.
                          Valid: ${!ROLE_UNITS[@]}
  --database-url=URL      Postgres URL (skips the interactive prompt).
  --listen-addr=:PORT     LISTEN_ADDR for constellation-api (default :8080).
  --version=vX.Y.Z        Release version to download (default: latest).
  --purge                 (uninstall.sh only) also remove the system user.
  -h, --help              This text.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-source)       FROM_SOURCE=1; shift ;;
    --upgrade)           UPGRADE=1; shift ;;
    --user)              USER_MODE=1; shift ;;
    --non-interactive)   NON_INTERACTIVE=1; shift ;;
    --roles=*)           ROLES_ARG="${1#--roles=}"; shift ;;
    --database-url=*)    DATABASE_URL_ARG="${1#--database-url=}"; shift ;;
    --listen-addr=*)     LISTEN_ADDR_ARG="${1#--listen-addr=}"; shift ;;
    --version=*)         DOWNLOAD_VERSION="${1#--version=}"; shift ;;
    --purge)             PURGE=1; shift ;;
    -h|--help)           usage; exit 0 ;;
    *)                   fail "unknown arg: $1 (try --help)" ;;
  esac
done

# --------------------------------------------------------------------------- user-mode rewrites

if [[ $USER_MODE -eq 1 ]]; then
  SYSTEMD_DIR="$HOME/.config/systemd/user"
  ETC_DIR="$HOME/.config/constellation"
  LIB_DIR="$HOME/.local/share/constellation"
  LOG_DIR="$HOME/.local/share/constellation/log"
  BIN_DIR="$HOME/.local/bin"
  SVC_USER=""           # blank => unit files patched to drop User=/Group=
  SVC_GROUP=""
  SYSTEMCTL="systemctl --user"
  log "user mode: paths rebased under \$HOME, systemctl=--user"
fi

# --------------------------------------------------------------------------- prereqs

check_prereqs() {
  log "checking prerequisites"
  if [[ $USER_MODE -eq 0 && $EUID -ne 0 ]]; then
    fail "not running as root — re-run with sudo, or pass --user for an unprivileged dev install"
  fi
  command -v systemctl >/dev/null || fail "systemd (systemctl) not found"
  # CPU + RAM sanity.
  local cpus mem_kb
  cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
  mem_kb="$(awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  [[ "$cpus" -ge 1 ]] || fail "need >= 1 CPU"
  if [[ "$mem_kb" -lt 1900000 ]]; then
    warn "system reports <2GB RAM (${mem_kb} kB); proceeding anyway"
  fi
  # libpcap is the canonical "host has packet capture" marker the runtime agent's deps look
  # for. We only warn — the agent will tell you in its own logs if it can't load.
  if [[ -n "${INSTALL_CHECK_PCAP:-1}" ]]; then
    if ! ldconfig -p 2>/dev/null | grep -q libpcap && ! ls /usr/lib*/libpcap* >/dev/null 2>&1; then
      warn "libpcap not detected — runtime-agent may need it on some kernels"
    fi
  fi
  command -v curl >/dev/null || warn "curl not found (needed for --upgrade and release download)"
  ok "prereqs ok (cpus=$cpus mem=${mem_kb}kB)"
}

# --------------------------------------------------------------------------- user

ensure_user() {
  [[ $USER_MODE -eq 1 ]] && return 0
  if ! getent group "$SVC_GROUP" >/dev/null; then
    log "creating group $SVC_GROUP"
    groupadd --system "$SVC_GROUP"
  fi
  if ! getent passwd "$SVC_USER" >/dev/null; then
    log "creating system user $SVC_USER"
    useradd --system --gid "$SVC_GROUP" --home-dir "$LIB_DIR" --shell /sbin/nologin \
      --comment "Constellation service account" "$SVC_USER"
  fi
  ok "user $SVC_USER:$SVC_GROUP ready"
}

# --------------------------------------------------------------------------- dirs

ensure_dirs() {
  log "creating directories"
  for d in "$ETC_DIR" "$LIB_DIR" "$LOG_DIR" "$BIN_DIR" "$SYSTEMD_DIR"; do
    mkdir -p "$d"
  done
  if [[ $USER_MODE -eq 0 ]]; then
    chown -R "$SVC_USER:$SVC_GROUP" "$LIB_DIR" "$LOG_DIR"
    chmod 0750 "$ETC_DIR"
    chown root:"$SVC_GROUP" "$ETC_DIR"
  fi
  ok "dirs: $ETC_DIR, $LIB_DIR, $LOG_DIR, $BIN_DIR, $SYSTEMD_DIR"
}

# --------------------------------------------------------------------------- postgres

detect_postgres() {
  if command -v pg_isready >/dev/null; then
    if pg_isready -q 2>/dev/null; then
      ok "local Postgres is up (pg_isready)"
      return 0
    fi
    # also try the common non-default port the user is running on this host
    if pg_isready -q -p 5433 2>/dev/null; then
      ok "local Postgres is up on :5433"
      return 0
    fi
  fi
  warn "no local Postgres detected"
  cat <<EOF
  To install locally:
    Ubuntu/Debian: sudo apt-get install -y postgresql-16 postgresql-16-pgvector
    RHEL/Rocky:    sudo dnf install -y postgresql16-server postgresql16-contrib pgvector_16
                   sudo /usr/pgsql-16/bin/postgresql-16-setup initdb
    SLES:          sudo zypper in postgresql16-server postgresql16-contrib postgresql16-pgvector
  Otherwise supply a DATABASE_URL pointing at an external server.
EOF
  return 1
}

# --------------------------------------------------------------------------- binaries

build_one() {
  local bin="$1"
  local target=""
  case "$bin" in
    "$DRIVER_BIN")
      target="$REPO_ROOT/deploy/e2e/scanner-driver"
      ;;
    *)
      target="$REPO_ROOT/cmd/$bin"
      ;;
  esac
  if [[ ! -d "$target" ]]; then
    warn "skip $bin — source dir $target not found"
    return 0
  fi
  log "building $bin"
  ( cd "$REPO_ROOT" && go build -o "/tmp/.cstn-build/$bin" "./${target#$REPO_ROOT/}" )
  install -m 0755 "/tmp/.cstn-build/$bin" "$BIN_DIR/$bin"
  ok "  -> $BIN_DIR/$bin"
}

build_binaries() {
  mkdir -p /tmp/.cstn-build
  if ! command -v go >/dev/null; then
    fail "--from-source requested but 'go' is not on PATH"
  fi
  for b in "${BINARIES[@]}" "$DRIVER_BIN"; do
    build_one "$b"
  done
}

download_binaries() {
  warn "release-download path is not wired to a real artifact server yet."
  warn "Re-run with --from-source against the cloned repo, or pre-populate $BIN_DIR."
  fail "no download backend available (version=$DOWNLOAD_VERSION)"
}

# --------------------------------------------------------------------------- install units + env

# Render a service file into $SYSTEMD_DIR, applying --user adjustments if needed.
install_unit() {
  local src="$SCRIPT_DIR/$1"
  local name; name="$(basename "$src")"
  [[ -f "$src" ]] || { warn "missing unit file: $src"; return 0; }
  if [[ $USER_MODE -eq 1 ]]; then
    # systemd --user: strip User=/Group= and capability lines (kernel disallows ambient
    # caps from a user manager), rewrite paths to ~/.local/...
    sed \
      -e '/^User=/d' \
      -e '/^Group=/d' \
      -e '/^AmbientCapabilities=/d' \
      -e '/^CapabilityBoundingSet=/d' \
      -e '/^NoNewPrivileges=false/d' \
      -e "s|/usr/local/bin|$BIN_DIR|g" \
      -e "s|/etc/constellation|$ETC_DIR|g" \
      -e "s|/var/lib/constellation|$LIB_DIR|g" \
      "$src" > "$SYSTEMD_DIR/$name"
  else
    install -m 0644 "$src" "$SYSTEMD_DIR/$name"
  fi
  ok "  unit -> $SYSTEMD_DIR/$name"
}

# Install env file from .example if not already present (preserve operator edits).
install_env() {
  local name="$1"
  local src="$SCRIPT_DIR/env/${name}.example"
  local dst="$ETC_DIR/$name"
  [[ -f "$src" ]] || { warn "no template for $name"; return 0; }
  if [[ -f "$dst" && $UPGRADE -eq 1 ]]; then
    ok "  env kept (upgrade): $dst"
    return 0
  fi
  if [[ -f "$dst" ]]; then
    ok "  env exists, leaving alone: $dst"
    return 0
  fi
  install -m 0640 "$src" "$dst"
  if [[ $USER_MODE -eq 0 ]]; then
    chown root:"$SVC_GROUP" "$dst"
  fi
  ok "  env -> $dst"
}

# --------------------------------------------------------------------------- secret helpers

gen_hex() {
  local nbytes="${1:-48}"
  if command -v openssl >/dev/null; then
    openssl rand -hex "$nbytes"
  else
    head -c "$nbytes" /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

# Set or update a KEY=VALUE in an env file, preserving comments.
set_env_var() {
  local file="$1" key="$2" value="$3"
  [[ -f "$file" ]] || { warn "env $file missing"; return 1; }
  if grep -qE "^${key}=" "$file"; then
    # Replace existing.
    local tmp; tmp="$(mktemp)"
    awk -v k="$key" -v v="$value" -F= '
      BEGIN { OFS="=" }
      $0 ~ "^" k "=" { printf "%s=%s\n", k, v; next }
      { print }
    ' "$file" > "$tmp"
    mv "$tmp" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
  chmod 0640 "$file"
}

# --------------------------------------------------------------------------- role picker

ALL_ROLES="api scanner operator runtime-agent discoverer audit-archiver scanner-driver"

pick_roles() {
  if [[ -n "$ROLES_ARG" ]]; then
    echo "$ROLES_ARG" | tr ',' ' '
    return
  fi
  if [[ $NON_INTERACTIVE -eq 1 ]]; then
    fail "--non-interactive requires --roles=..."
  fi
  local picked=()
  echo
  echo "${C_BLD}Select roles to enable on this host${C_RST} (y/N each):"
  for r in $ALL_ROLES; do
    local default="N"
    case "$r" in api|scanner) default="Y" ;; esac
    local prompt="  enable $r? [${default}]: "
    read -r -p "$prompt" ans </dev/tty || ans=""
    ans="${ans:-$default}"
    if [[ "$ans" =~ ^[Yy] ]]; then
      picked+=("$r")
    fi
  done
  printf '%s\n' "${picked[@]}"
}

# --------------------------------------------------------------------------- ask for DATABASE_URL

ask_db_url() {
  if [[ -n "$DATABASE_URL_ARG" ]]; then
    echo "$DATABASE_URL_ARG"; return
  fi
  if [[ $NON_INTERACTIVE -eq 1 ]]; then
    fail "--non-interactive requires --database-url=..."
  fi
  local default="postgres:///constellation?host=/var/run/postgresql"
  if pg_isready -q -p 5432 2>/dev/null; then :; else
    default="postgres://constellation:constellation@127.0.0.1:5432/constellation?sslmode=disable"
  fi
  read -r -p "DATABASE_URL [$default]: " ans </dev/tty || ans=""
  echo "${ans:-$default}"
}

# --------------------------------------------------------------------------- enable + verify

enable_and_wait() {
  local unit="$1"
  log "enabling $unit"
  $SYSTEMCTL daemon-reload
  $SYSTEMCTL enable --now "$unit" || true
  # Wait up to 30s for active.
  local i=0
  while (( i < 30 )); do
    local st
    st="$($SYSTEMCTL is-active "$unit" 2>/dev/null || true)"
    case "$st" in
      active)        ok "$unit active"; return 0 ;;
      activating)    : ;;
      inactive|failed)
        # oneshot timers may report inactive after they fire — acceptable for .timer units
        if [[ "$unit" == *.timer ]]; then ok "$unit ok (timer)"; return 0; fi
        ;;
    esac
    sleep 1
    i=$((i+1))
  done
  warn "$unit did not reach active in 30s (last status: ${st:-unknown})"
  $SYSTEMCTL status --no-pager --lines=20 "$unit" || true
  return 1
}

# --------------------------------------------------------------------------- main

main() {
  log "Constellation systemd installer (mode: $([[ $USER_MODE -eq 1 ]] && echo user || echo system))"

  check_prereqs
  ensure_user
  ensure_dirs

  if [[ $FROM_SOURCE -eq 1 || $UPGRADE -eq 1 ]]; then
    build_binaries
  else
    # Allow already-placed binaries (e.g. operator pre-staged them).
    local missing=0
    for b in "${BINARIES[@]}"; do
      [[ -x "$BIN_DIR/$b" ]] || missing=1
    done
    if [[ $missing -eq 1 ]]; then
      warn "binaries missing from $BIN_DIR — falling back to --from-source"
      if command -v go >/dev/null && [[ -d "$REPO_ROOT/cmd" ]]; then
        build_binaries
      else
        download_binaries
      fi
    fi
  fi

  detect_postgres || true

  # Install ALL unit files (cheap; users decide which to enable).
  log "installing unit files"
  for u in \
      constellation-api.service \
      constellation-scanner.service \
      constellation-scanner@.service \
      constellation-operator.service \
      constellation-runtime-agent.service \
      constellation-discoverer.service \
      constellation-discoverer@.service \
      constellation-scanner-driver.service \
      constellation-audit-archiver.service \
      constellation-audit-archiver.timer; do
    install_unit "$u"
  done

  log "installing env file templates"
  for e in api.env scanner.env operator.env runtime-agent.env discoverer.env audit-archiver.env scanner-driver.env; do
    install_env "$e"
  done

  # Pick roles.
  log "selecting roles"
  local roles
  roles="$(pick_roles | xargs)"
  [[ -n "$roles" ]] || { warn "no roles selected; exiting after file install"; exit 0; }
  ok "roles: $roles"

  # DATABASE_URL applied to every role's env that has DATABASE_URL.
  local db_url
  db_url="$(ask_db_url)"
  for role in api discoverer audit-archiver scanner-driver; do
    local f="$ETC_DIR/${ROLE_ENVS[$role]}"
    [[ -f "$f" ]] && set_env_var "$f" DATABASE_URL "$db_url"
  done

  # api: JWT_KEYS + LISTEN_ADDR
  # A5: by default we do NOT generate a symmetric JWT_KEYS. With it empty, the api
  # signs sessions RS256 using a shared keypair it generates + persists in the
  # session_signing_keys table on first boot (and rotates via
  # `constellation-api --rotate-jwt-key`). A raw hex secret would instead downgrade
  # sessions to HS256, which is now rejected unless CONSTELLATION_ALLOW_HS256_JWT=true.
  # We blank out the REPLACE_ME placeholder so the RS256 DB path takes over, while
  # leaving any operator-provided JWT_KEYS untouched.
  if [[ -f "$ETC_DIR/api.env" ]]; then
    if grep -q "^JWT_KEYS=REPLACE_ME" "$ETC_DIR/api.env"; then
      set_env_var "$ETC_DIR/api.env" JWT_KEYS ""
      ok "JWT_KEYS left empty; api will sign sessions RS256 with the DB-backed keypair"
    else
      ok "JWT_KEYS already set by operator; leaving alone"
    fi
    if [[ -n "$LISTEN_ADDR_ARG" ]]; then
      set_env_var "$ETC_DIR/api.env" LISTEN_ADDR "$LISTEN_ADDR_ARG"
    fi
  fi

  # scanner: token
  if [[ -f "$ETC_DIR/scanner.env" ]]; then
    if grep -q "^CONSTELLATION_SCANNER_TOKEN=REPLACE_ME" "$ETC_DIR/scanner.env"; then
      set_env_var "$ETC_DIR/scanner.env" CONSTELLATION_SCANNER_TOKEN "$(gen_hex 32)"
      ok "generated scanner token (register with: constellationctl tokens register-scanner)"
    fi
  fi
  # runtime-agent: token
  if [[ -f "$ETC_DIR/runtime-agent.env" ]]; then
    if grep -q "^RUNTIME_AGENT_TOKEN=REPLACE_ME" "$ETC_DIR/runtime-agent.env"; then
      set_env_var "$ETC_DIR/runtime-agent.env" RUNTIME_AGENT_TOKEN "$(gen_hex 32)"
      ok "generated runtime-agent token (register with: constellationctl tokens register-runtime-agent)"
    fi
  fi

  # Enable selected units.
  for role in $roles; do
    local unit="${ROLE_UNITS[$role]:-}"
    [[ -n "$unit" ]] || { warn "unknown role: $role"; continue; }
    enable_and_wait "$unit" || true
    if [[ "$role" == "audit-archiver" ]]; then
      enable_and_wait constellation-audit-archiver.timer || true
    fi
  done

  echo
  log "summary"
  for role in $roles; do
    local unit="${ROLE_UNITS[$role]:-}"
    printf "  %-22s %s\n" "$unit" "$($SYSTEMCTL is-active "$unit" 2>/dev/null || echo unknown)"
  done

  cat <<EOF

${C_GRN}install complete${C_RST}

Next steps:
  1. Edit env files in $ETC_DIR  (e.g. CORS_ORIGINS, OIDC, S3 creds)
  2. Restart affected units:     $SYSTEMCTL restart <unit>
  3. Tail logs:                  journalctl${USER_MODE:+ --user} -u <unit> -f
  4. Reconfigure interactively:  ./reconfigure.sh <role>
  5. Health-check the API:       curl -sf http://localhost\$(grep ^LISTEN_ADDR $ETC_DIR/api.env | cut -d= -f2)/healthz

EOF
}

main "$@"
