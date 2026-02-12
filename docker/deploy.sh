#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
API_SCALE="${2:-2}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

preflight() {
    log_info "Running pre-flight checks..."

    if ! command -v docker &>/dev/null; then
        log_error "Docker not installed. Run: curl -fsSL https://get.docker.com | sh"
        exit 1
    fi

    if ! docker compose version &>/dev/null; then
        log_error "Docker Compose V2 not found."
        exit 1
    fi

    if [ ! -f "$PROJECT_ROOT/.env" ]; then
        log_error ".env file not found at $PROJECT_ROOT/.env"
        exit 1
    fi

    log_info "All checks passed."
}

apply_sysctl() {
    log_info "Applying kernel tuning..."
    if [ -f "$SCRIPT_DIR/sysctl-tuning.conf" ]; then
        cp "$SCRIPT_DIR/sysctl-tuning.conf" /etc/sysctl.d/99-scamintelli.conf
        sysctl --system > /dev/null 2>&1
        log_info "Kernel parameters applied."
    else
        log_warn "sysctl-tuning.conf not found, skipping."
    fi
}

apply_ulimits() {
    log_info "Applying ulimit configuration..."
    if [ -f "$SCRIPT_DIR/ulimits.conf" ]; then
        cp "$SCRIPT_DIR/ulimits.conf" /etc/security/limits.d/99-scamintelli.conf
        log_info "ulimits applied (effective after next login)."
    else
        log_warn "ulimits.conf not found, skipping."
    fi
}

deploy() {
    log_info "Building Docker images..."
    docker compose -f "$COMPOSE_FILE" build --no-cache

    log_info "Starting services with api scale=${API_SCALE}..."
    docker compose -f "$COMPOSE_FILE" up -d --scale api="${API_SCALE}" --remove-orphans

    log_info "Waiting for services to become healthy..."
    sleep 10

    local retries=30
    while [ $retries -gt 0 ]; do
        if curl -sf http://localhost/api/v1/health > /dev/null 2>&1; then
            log_info "API is healthy and responding!"
            break
        fi
        retries=$((retries - 1))
        sleep 2
    done

    if [ $retries -eq 0 ]; then
        log_error "Health check failed after 60s. Check logs:"
        docker compose -f "$COMPOSE_FILE" logs --tail=50
        exit 1
    fi
}

show_status() {
    echo ""
    log_info "ScamIntelli deployed successfully!"
    echo ""
    log_info "  API Scale:      ${API_SCALE} containers"
    log_info "  Workers/cont:   2 (Gunicorn + Uvicorn)"
    log_info "  Total workers:  $((API_SCALE * 2))"
    log_info "  Endpoint:       http://localhost/api/v1/health"
    echo ""
    log_info "  Useful commands:"
    log_info "    Logs:    docker compose -f $COMPOSE_FILE logs -f"
    log_info "    Scale:   docker compose -f $COMPOSE_FILE up -d --scale api=N"
    log_info "    Stop:    docker compose -f $COMPOSE_FILE down"
    log_info "    Status:  docker compose -f $COMPOSE_FILE ps"
    echo ""
    docker compose -f "$COMPOSE_FILE" ps
}

main() {
    log_info "ScamIntelli Production Deployment"
    log_info "Target: m7i-flex.large (2 vCPU / 8 GB RAM)"
    echo ""

    preflight

    if [ "$(id -u)" -eq 0 ]; then
        apply_sysctl
        apply_ulimits
    else
        log_warn "Not running as root — skipping sysctl/ulimits (run with sudo for full setup)"
    fi

    deploy
    show_status
}

main "$@"
