#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
SYSCTL_CONF="$SCRIPT_DIR/sysctl-tuning.conf"
ULIMITS_CONF="$SCRIPT_DIR/ulimits.conf"
ACTION="${1:-deploy}"
API_SCALE="${2:-2}"
WORKER_SCALE="${3:-1}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${CYAN}[STEP]${NC}  $1"; }

usage() {
    echo "Usage: $0 [ACTION] [API_SCALE] [WORKER_SCALE]"
    echo ""
    echo "Actions:"
    echo "  deploy       First-time full deploy (default)"
    echo "  update       Rebuild & rolling-restart, preserving Redis/Neo4j data"
    echo "  restart      Restart containers without rebuilding"
    echo "  status       Show current service status"
    echo "  verify       Run Redis + ML model verification only"
    echo "  stop         Stop all services (data volumes preserved)"
    echo "  destroy      Stop all services AND remove data volumes"
    echo ""
    echo "Examples:"
    echo "  sudo $0 deploy 2 1        # First deploy: 2 API, 1 Worker"
    echo "  sudo $0 update 3 2        # Update code: 3 API, 2 Workers (data safe)"
    echo "  $0 status                 # Show service status"
    exit 0
}

preflight() {
    log_step "Running pre-flight checks..."

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

    TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    TOTAL_MEM_MB=$((TOTAL_MEM_KB / 1024))
    CPU_COUNT=$(nproc)

    if [ "$TOTAL_MEM_MB" -lt 4096 ]; then
        log_error "Minimum 4GB RAM required. Found: ${TOTAL_MEM_MB}MB"
        exit 1
    fi

    if [ "$CPU_COUNT" -lt 2 ]; then
        log_warn "Only ${CPU_COUNT} CPU(s) detected. Performance may degrade."
    fi

    DISK_AVAIL=$(df -BM "$PROJECT_ROOT" | tail -1 | awk '{print $4}' | tr -d 'M')
    if [ "$DISK_AVAIL" -lt 5120 ]; then
        log_warn "Low disk: ${DISK_AVAIL}MB available, recommend 5GB+"
    fi

    log_info "Host: ${CPU_COUNT} vCPU, ${TOTAL_MEM_MB}MB RAM, ${DISK_AVAIL}MB disk free"
}

apply_sysctl() {
    log_step "Applying kernel tuning..."

    if [ ! -f "$SYSCTL_CONF" ]; then
        log_warn "sysctl-tuning.conf not found at $SYSCTL_CONF, skipping"
        return
    fi

    cp "$SYSCTL_CONF" /etc/sysctl.d/99-scamintelli.conf
    sysctl --system > /dev/null 2>&1
    log_info "Kernel parameters applied from sysctl-tuning.conf"
}

apply_ulimits() {
    log_step "Applying ulimit configuration..."

    if [ ! -f "$ULIMITS_CONF" ]; then
        log_warn "ulimits.conf not found at $ULIMITS_CONF, skipping"
        return
    fi

    cp "$ULIMITS_CONF" /etc/security/limits.d/99-scamintelli.conf
    log_info "ulimits applied from ulimits.conf (effective after next login)"
}

setup_cloudflare() {
    log_step "Configuring Cloudflare proxy trust..."

    if [ ! -d "$SCRIPT_DIR/nginx/certs" ]; then
        mkdir -p "$SCRIPT_DIR/nginx/certs"
    fi

    if [ ! -f "$SCRIPT_DIR/nginx/certs/origin.pem" ] || [ ! -f "$SCRIPT_DIR/nginx/certs/origin-key.pem" ]; then
        log_warn "Cloudflare origin certificates not found in $SCRIPT_DIR/nginx/certs/"
        log_warn "Expected: origin.pem and origin-key.pem"
        log_warn "Generate at: Cloudflare Dashboard > SSL/TLS > Origin Server > Create Certificate"
    fi

    CF_IPS_V4=$(curl -sf https://www.cloudflare.com/ips-v4 2>/dev/null || true)
    CF_IPS_V6=$(curl -sf https://www.cloudflare.com/ips-v6 2>/dev/null || true)

    if [ -n "$CF_IPS_V4" ]; then
        CF_REALIP_CONF="$SCRIPT_DIR/nginx/conf.d/cloudflare-realip.conf"
        {
            echo "# Cloudflare IP ranges - auto-generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
            echo "$CF_IPS_V4" | while read -r cidr; do
                [ -n "$cidr" ] && echo "set_real_ip_from $cidr;"
            done
            if [ -n "$CF_IPS_V6" ]; then
                echo "$CF_IPS_V6" | while read -r cidr; do
                    [ -n "$cidr" ] && echo "set_real_ip_from $cidr;"
                done
            fi
            echo "real_ip_header CF-Connecting-IP;"
            echo "real_ip_recursive on;"
        } > "$CF_REALIP_CONF"
        log_info "Cloudflare real IP config updated with latest IP ranges."
    else
        log_warn "Could not fetch Cloudflare IPs. Using static ranges in default.conf."
    fi
}

wait_healthy() {
    local service="$1"
    local url="$2"
    local max_retries="${3:-30}"
    local interval="${4:-2}"

    log_info "Waiting for ${service} to become healthy..."

    local retries=$max_retries
    while [ $retries -gt 0 ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            log_info "${service} is healthy!"
            return 0
        fi
        retries=$((retries - 1))
        sleep "$interval"
    done

    log_error "${service} health check failed after $((max_retries * interval))s"
    return 1
}

compose_profiles() {
    local profiles=""
    source "$PROJECT_ROOT/.env" 2>/dev/null || true
    if [ "${NEO4J_ENABLED:-false}" = "true" ]; then
        profiles="--profile neo4j"
    fi
    echo "$profiles"
}

deploy() {
    log_step "Building Docker images (fresh build)..."
    docker compose -f "$COMPOSE_FILE" $(compose_profiles) build --no-cache

    log_step "Starting services (api=${API_SCALE}, worker=${WORKER_SCALE})..."
    docker compose -f "$COMPOSE_FILE" $(compose_profiles) up -d \
        --scale api="${API_SCALE}" \
        --scale worker="${WORKER_SCALE}" \
        --remove-orphans

    post_deploy_checks
}

update() {
    log_step "Building Docker images (incremental, data volumes preserved)..."
    docker compose -f "$COMPOSE_FILE" $(compose_profiles) build

    log_step "Rolling update (api=${API_SCALE}, worker=${WORKER_SCALE})..."
    docker compose -f "$COMPOSE_FILE" $(compose_profiles) up -d \
        --scale api="${API_SCALE}" \
        --scale worker="${WORKER_SCALE}" \
        --remove-orphans \
        --no-recreate-deps

    log_info "Redis and Neo4j data volumes are untouched."
    post_deploy_checks
}

restart_services() {
    log_step "Restarting containers (no rebuild, data preserved)..."
    docker compose -f "$COMPOSE_FILE" $(compose_profiles) restart api worker nginx
    post_deploy_checks
}

stop_services() {
    log_step "Stopping all services (data volumes preserved)..."
    docker compose -f "$COMPOSE_FILE" $(compose_profiles) down
    log_info "Containers removed. Data volumes (redis_data, neo4j_data) are preserved."
    log_info "Use '$0 deploy' or '$0 update' to bring services back up."
}

destroy_services() {
    log_warn "This will DELETE all data volumes (Redis, Neo4j, sessions)!"
    read -rp "Type 'yes' to confirm: " confirm
    if [ "$confirm" = "yes" ]; then
        docker compose -f "$COMPOSE_FILE" $(compose_profiles) down -v
        log_info "All containers and volumes destroyed."
    else
        log_info "Aborted."
    fi
}

post_deploy_checks() {
    sleep 5

    if ! docker compose -f "$COMPOSE_FILE" ps redis | grep -q "running"; then
        log_error "Redis failed to start"
        docker compose -f "$COMPOSE_FILE" logs redis --tail=20
        exit 1
    fi
    log_info "Redis verified running."

    if docker compose -f "$COMPOSE_FILE" ps neo4j 2>/dev/null | grep -q "running"; then
        wait_healthy "Neo4j" "http://localhost:7474" 30 3 || log_warn "Neo4j not ready yet, API will retry"
    fi

    if ! wait_healthy "API" "http://localhost/api/v1/health" 40 2; then
        log_error "Dumping API logs:"
        docker compose -f "$COMPOSE_FILE" logs api --tail=50
        exit 1
    fi

    WORKER_RUNNING=$(docker compose -f "$COMPOSE_FILE" ps worker --format json 2>/dev/null | grep -c '"running"' || echo "0")
    if [ "$WORKER_RUNNING" -ge 1 ]; then
        log_info "Workers verified running (${WORKER_RUNNING} containers)."
    else
        log_warn "Workers may not be running. Check: docker compose -f $COMPOSE_FILE logs worker"
    fi
}

verify_redis() {
    log_step "Verifying Redis performance..."

    REDIS_CONTAINER=$(docker compose -f "$COMPOSE_FILE" ps redis -q 2>/dev/null | head -1)
    if [ -z "$REDIS_CONTAINER" ]; then
        log_warn "Cannot verify Redis - container not found"
        return
    fi

    REDIS_INFO=$(docker exec "$REDIS_CONTAINER" redis-cli info server 2>/dev/null || true)
    REDIS_VERSION=$(echo "$REDIS_INFO" | grep redis_version | cut -d: -f2 | tr -d '\r')
    REDIS_MEM=$(docker exec "$REDIS_CONTAINER" redis-cli info memory 2>/dev/null | grep used_memory_human | cut -d: -f2 | tr -d '\r')

    LATENCY=$(docker exec "$REDIS_CONTAINER" redis-cli --latency -c 10 2>/dev/null | tail -1 || true)

    log_info "Redis v${REDIS_VERSION}, Memory: ${REDIS_MEM}"
    if [ -n "$LATENCY" ]; then
        log_info "Redis latency: ${LATENCY}"
    fi

    PING_RESULT=$(docker exec "$REDIS_CONTAINER" redis-cli ping 2>/dev/null || echo "FAIL")
    if [ "$PING_RESULT" != "PONG" ]; then
        log_error "Redis PING failed"
        exit 1
    fi
    log_info "Redis PING: PONG"
}

verify_ml_model() {
    log_step "Verifying ML model status..."

    API_CONTAINER=$(docker compose -f "$COMPOSE_FILE" ps api -q 2>/dev/null | head -1)
    if [ -z "$API_CONTAINER" ]; then
        log_warn "Cannot verify ML model - API container not found"
        return
    fi

    HEALTH=$(curl -sf http://localhost/api/v1/health/ready 2>/dev/null || echo "{}")

    ML_STATUS=$(echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('checks',{}).get('ml_model','unknown'))" 2>/dev/null || echo "unknown")
    REDIS_STATUS=$(echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('checks',{}).get('redis','unknown'))" 2>/dev/null || echo "unknown")

    log_info "ML Model loaded: ${ML_STATUS}"
    log_info "Redis connected: ${REDIS_STATUS}"

    if [ "$ML_STATUS" != "True" ]; then
        log_warn "ML model not trained. Training now..."
        API_KEY=$(grep -oP '^API_KEY=\K.*' "$PROJECT_ROOT/.env" 2>/dev/null || echo "")
        if [ -n "$API_KEY" ]; then
            TRAIN_RESULT=$(curl -sf -X POST \
                -H "x-api-key: $API_KEY" \
                "http://localhost/api/v1/train" 2>/dev/null || echo '{"status":"failed"}')
            TRAIN_STATUS=$(echo "$TRAIN_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','failed'))" 2>/dev/null || echo "failed")
            if [ "$TRAIN_STATUS" = "success" ]; then
                log_info "ML model trained successfully"
            else
                log_warn "ML training failed (can be retrained later via POST /api/v1/train)"
            fi
        else
            log_warn "API_KEY not found in .env, skipping auto-train"
        fi
    fi
}

show_status() {
    echo ""
    log_info "ScamIntelli Service Status"
    echo ""
    log_info "  Host:          $(nproc) vCPU / $(($(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024))MB RAM"
    log_info "  OS:            $(lsb_release -ds 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"')"
    log_info "  Proxy:         Cloudflare (CF-Connecting-IP trusted)"
    log_info "  Endpoint:      https://scamintelli.mysterysd.in/api/v1/health"
    echo ""

    VOLUMES=$(docker volume ls --format '{{.Name}}' 2>/dev/null | grep scamintelli || true)
    if [ -n "$VOLUMES" ]; then
        log_info "  Data Volumes:"
        echo "$VOLUMES" | while read -r vol; do
            SIZE=$(docker system df -v 2>/dev/null | grep "$vol" | awk '{print $4}' || echo "unknown")
            log_info "    $vol ($SIZE)"
        done
    fi

    echo ""
    log_info "  Commands:"
    log_info "    Update:      sudo $0 update [API_SCALE] [WORKER_SCALE]"
    log_info "    Logs:        docker compose -f $COMPOSE_FILE logs -f"
    log_info "    Scale API:   docker compose -f $COMPOSE_FILE up -d --scale api=N"
    log_info "    Scale Work:  docker compose -f $COMPOSE_FILE up -d --scale worker=N"
    log_info "    Stop:        $0 stop     (preserves data)"
    log_info "    Destroy:     $0 destroy  (removes data)"
    log_info "    Status:      docker compose -f $COMPOSE_FILE ps"
    log_info "    Redis CLI:   docker compose -f $COMPOSE_FILE exec redis redis-cli"
    echo ""
    docker compose -f "$COMPOSE_FILE" ps
}

main() {
    case "$ACTION" in
        help|-h|--help)
            usage
            ;;
        status)
            show_status
            exit 0
            ;;
        verify)
            verify_redis
            verify_ml_model
            exit 0
            ;;
        stop)
            stop_services
            exit 0
            ;;
        destroy)
            destroy_services
            exit 0
            ;;
    esac

    echo ""
    log_info "ScamIntelli Production Deployment"
    log_info "Target: m7i-flex.large | Ubuntu 24.04 | Cloudflare Proxied"
    log_info "Action: ${ACTION}"
    echo ""

    preflight

    if [ "$(id -u)" -eq 0 ]; then
        apply_sysctl
        apply_ulimits
    else
        log_warn "Not running as root — skipping sysctl/ulimits (run with sudo for full tuning)"
    fi

    setup_cloudflare

    case "$ACTION" in
        deploy)
            deploy
            ;;
        update)
            update
            ;;
        restart)
            restart_services
            ;;
        *)
            log_error "Unknown action: $ACTION"
            usage
            ;;
    esac

    verify_redis
    verify_ml_model
    show_status
}

main "$@"
