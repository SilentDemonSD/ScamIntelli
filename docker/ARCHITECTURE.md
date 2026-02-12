###############################################################################
# ScamIntelli — Production Architecture & Operations Guide
# Infrastructure: AWS m7i-flex.large | 2 vCPU | 8 GB RAM | 32 GB gp3
# OS: Ubuntu 24.04 LTS | CDN: Cloudflare (Full Strict SSL)
###############################################################################


## Architecture Overview

```
                    ┌──────────────┐
                    │  Cloudflare  │  ← TLS termination, DDoS, CDN, HTTP/2
                    │  (Edge/CDN)  │
                    └──────┬───────┘
                           │ HTTP (port 80)
                    ┌──────┴───────┐
                    │    Nginx     │  ← Reverse proxy, gzip, least_conn LB
                    │  (container) │     Rate limiting, security headers
                    └──────┬───────┘
                           │ upstream keepalive
              ┌────────────┼────────────┐
              │            │            │
        ┌─────┴─────┐ ┌───┴─────┐ ┌────┴────┐
        │  API :8000 │ │ API :8000│ │API :8000│  ← FastAPI containers
        │ (2 workers)│ │(2 work.) │ │(2 work.)│     Gunicorn + Uvicorn
        └─────┬──────┘ └────┬────┘ └────┬────┘
              │              │           │
              └──────────────┼───────────┘
                             │
                    ┌────────┴────────┐
                    │   Redis :6379   │  ← Session store, cache
                    │  (512 MB limit) │     LRU eviction, AOF persist
                    └─────────────────┘
```


## Container Resource Budget (8 GB total, ~7 GB usable)

| Container       | CPU Limit | CPU Reserve | RAM Limit | RAM Reserve | Count |
|-----------------|-----------|-------------|-----------|-------------|-------|
| **Nginx**       | 0.20      | 0.05        | 128 MB    | 32 MB       | 1     |
| **API**         | 0.80      | 0.30        | 2560 MB   | 512 MB      | 2-3   |
| **Redis**       | 0.20      | 0.05        | 768 MB    | 256 MB      | 1     |
| **OS + Docker** | —         | —           | ~1 GB     | —           | —     |

### Memory math (with `--scale api=2`):

```
Nginx:             128 MB
API × 2:         5,120 MB  (2,560 × 2)
Redis:             768 MB
OS + Docker:     ~1,000 MB
─────────────────────────
Total:           ~7,016 MB ✓ (fits in 8 GB)
```

### Memory math (with `--scale api=3` — maximum):

```
Nginx:             128 MB
API × 3:         7,680 MB  (2,560 × 3) ← EXCEEDS LIMIT
```

> **With 3 containers, reduce API memory limit to 1536 MB:**
> API × 3: 4,608 MB → Total ~6,504 MB ✓


## Deployment Commands

```bash
# ── First-time setup ────────────────────────────────────────────────────
cd /opt/scamintelli/docker
sudo ./deploy.sh                    # Default: 2 API containers

# ── Manual deployment ───────────────────────────────────────────────────
docker compose build --no-cache
docker compose up -d --scale api=2 --remove-orphans

# ── Scale up (traffic spike) ───────────────────────────────────────────
docker compose up -d --scale api=3  # Max for 2 vCPU

# ── Scale down (normal traffic) ────────────────────────────────────────
docker compose up -d --scale api=2

# ── Zero-downtime restart (rolling) ────────────────────────────────────
docker compose up -d --scale api=3  # Add extra container first
sleep 15                             # Wait for health check
docker compose up -d --scale api=2  # Remove old one

# ── View logs ───────────────────────────────────────────────────────────
docker compose logs -f api          # API logs
docker compose logs -f nginx        # Nginx access/error logs
docker compose ps                   # Container status

# ── Emergency stop ──────────────────────────────────────────────────────
docker compose down
```


## Scaling Strategy

### How `docker compose up --scale api=N` works

1. Docker Compose creates N replicas of the `api` service
2. All replicas register under the DNS name `api` in the Docker network
3. Nginx resolves `api:8000` → Docker's internal round-robin DNS returns all container IPs
4. Nginx's `least_conn` picks the container with fewest active connections

### Recommended container count for 2 vCPU

| Scale | Containers | Workers | Total Processes | CPU Pressure | Verdict         |
|-------|-----------|---------|-----------------|-------------|-----------------|
| 1     | 1 API     | 2       | 2               | Low         | Dev/staging     |
| **2** | **2 API** | **4**   | **4**           | **Optimal** | **Production**  |
| 3     | 3 API     | 6       | 6               | High        | Spike handling  |
| 4+    | 4+ API    | 8+      | 8+              | Thrashing   | **AVOID**       |

> **Recommendation: `--scale api=2` for steady state**
> Scale to 3 only during verified traffic spikes. Never exceed 3 on 2 vCPU.

### Why 2 workers per container?

- Each Uvicorn worker runs a full async event loop (handles 100s of concurrent connections)
- 2 workers per container × 2 containers = 4 total worker processes = 2 per vCPU
- Preloaded app (`preload_app = True`) means workers share memory via copy-on-write
- `max_requests=2000` recycles workers to prevent memory leaks without downtime


## Performance Estimates

### Simple JSON endpoint (`GET /api/v1/health`)

| Scale  | Est. RPS  | P50 Latency | P99 Latency |
|--------|----------|-------------|-------------|
| api=1  | 3,000-5,000  | <1ms   | ~3ms        |
| api=2  | 5,000-8,000  | <1ms   | ~5ms        |
| api=3  | 7,000-10,000 | <2ms   | ~8ms        |

### With Gemini API call + Redis (`POST /api/v1/message`)

| Scale  | Est. RPS | P50 Latency | P99 Latency | Bottleneck        |
|--------|---------|-------------|-------------|-------------------|
| api=1  | 30-80   | ~200ms      | ~800ms      | Gemini API RTT    |
| api=2  | 50-140  | ~200ms      | ~900ms      | Gemini API RTT    |
| api=3  | 70-180  | ~250ms      | ~1.2s       | CPU (ML models)   |

> The real bottleneck is the external Gemini API call latency (~150-500ms).
> Local processing (scam detection, ML scoring) adds ~20-50ms.
> Scaling containers helps concurrency but can't reduce single-request latency.

### Total effective concurrency capacity

| Scale  | Concurrent Connections | Reasoning                              |
|--------|----------------------|----------------------------------------|
| api=1  | ~500                 | 2 workers × ~250 async connections     |
| api=2  | ~1,000               | 4 workers × ~250 async connections     |
| api=3  | ~1,500               | 6 workers × ~250 async connections     |


## OS-Level Tuning

### sysctl parameters (applied via deploy.sh)

```bash
sudo cp docker/sysctl-tuning.conf /etc/sysctl.d/99-scamintelli.conf
sudo sysctl --system
```

Key parameters:
- `net.core.somaxconn=4096` — Connection backlog for high-RPS
- `net.ipv4.tcp_tw_reuse=1` — Reuse TIME_WAIT sockets
- `net.ipv4.tcp_fin_timeout=15` — Fast connection cleanup
- `vm.swappiness=10` — Minimize swap usage (keep app in RAM)
- `net.ipv4.tcp_congestion_control=bbr` — Google BBR for cloud networks
- `fs.file-max=262144` — System-wide file descriptor limit

### ulimit settings

```bash
sudo cp docker/ulimits.conf /etc/security/limits.d/99-scamintelli.conf
```

- `nofile` 65536 — Enough for thousands of concurrent connections
- `nproc` 4096 — Enough for Docker container processes
- Core dumps disabled in production


## Cloudflare Configuration

### DNS
- A record → EC2 public IP, **Proxy enabled** (orange cloud)
- SSL mode: **Full (Strict)**

### Recommended Cloudflare settings

| Setting                  | Value                                    |
|--------------------------|------------------------------------------|
| SSL/TLS                  | Full (Strict)                            |
| Minimum TLS Version      | TLS 1.2                                  |
| Always Use HTTPS         | ON                                       |
| HTTP/2                   | ON (edge-to-client)                      |
| HTTP/3 (QUIC)            | ON                                       |
| Brotli                   | ON                                       |
| Auto Minify              | OFF (API, no static assets)              |
| Browser Cache TTL        | Respect Existing Headers                 |
| Caching Level            | Standard                                 |
| Security Level           | High                                     |
| Bot Fight Mode           | ON                                       |
| Challenge Passage        | 30 minutes                               |
| Under Attack Mode        | OFF (enable during DDoS)                 |

### Cloudflare Page Rules (optional)

```
/api/v1/*  → Cache Level: Bypass, SSL: Full (Strict)
```

### Cloudflare WAF Rules (recommended)

- Block requests without valid User-Agent
- Rate limit: 100 req/10s per IP on `/api/v1/message`
- Challenge suspicious traffic from known bot ASNs


## Monitoring & Observability

### Health check endpoints

```bash
# Nginx health (internal)
curl http://localhost/nginx-health

# API health (through nginx)
curl http://localhost/api/v1/health

# Direct container health (debugging)
docker compose exec api curl http://localhost:8000/api/v1/health
```

### Resource monitoring

```bash
# Real-time container stats
docker stats

# Nginx access logs (request timing)
docker compose logs -f nginx | grep 'rt='

# Check upstream response times
docker compose exec nginx cat /var/log/nginx/access.log | awk '{print $NF}' | sort -n

# Redis memory usage
docker compose exec redis redis-cli info memory
```

### Alert thresholds

| Metric                 | Warning    | Critical   | Action                    |
|------------------------|-----------|------------|---------------------------|
| CPU per container      | >70%      | >90%       | Scale up or reduce workers|
| RAM per container      | >80%      | >95%       | Check for memory leaks    |
| Nginx 5xx rate         | >1%       | >5%        | Check API logs            |
| Redis memory           | >400 MB   | >480 MB    | Review eviction policy    |
| P99 latency            | >1s       | >3s        | Profile slow endpoints    |
| Connection queue depth | >100      | >500       | Scale up containers       |


## Future Migration Path: Docker Compose → Kubernetes

### What stays the same (zero redesign)

| Component             | Docker Compose           | Kubernetes              |
|-----------------------|--------------------------|-------------------------|
| App image             | Same Dockerfile          | Same Dockerfile         |
| Gunicorn config       | Same gunicorn.conf.py    | Same (ConfigMap)        |
| Env vars              | .env file                | K8s Secret/ConfigMap    |
| Redis                 | Container                | StatefulSet / ElastiCache|
| Health checks         | Same endpoints           | Same (liveness/readiness)|
| Nginx                 | Container                | Ingress Controller      |

### Migration steps

1. **Push image to ECR**
   ```bash
   aws ecr create-repository --repository-name scamintelli
   docker tag scamintelli:latest <account>.dkr.ecr.<region>.amazonaws.com/scamintelli:v1
   docker push <account>.dkr.ecr.<region>.amazonaws.com/scamintelli:v1
   ```

2. **Create EKS cluster** (or use existing)
   ```bash
   eksctl create cluster --name scamintelli --region eu-central-1 \
     --nodegroup-name workers --node-type m7i-flex.large --nodes 2
   ```

3. **Convert docker-compose.yml → K8s manifests**
   - `docker-compose.yml` API service → `Deployment` + `Service`
   - Nginx → `Ingress` (with AWS ALB Ingress Controller)
   - Redis → `StatefulSet` or migrate to ElastiCache
   - env vars → `Secret` + `ConfigMap`
   - Resource limits → Pod `resources.limits`

4. **Enable HPA**
   ```yaml
   apiVersion: autoscaling/v2
   kind: HorizontalPodAutoscaler
   metadata:
     name: scamintelli-api
   spec:
     scaleTargetRef:
       apiVersion: apps/v1
       kind: Deployment
       name: scamintelli-api
     minReplicas: 2
     maxReplicas: 10
     metrics:
       - type: Resource
         resource:
           name: cpu
           target:
             type: Utilization
             averageUtilization: 70
   ```

5. **Add ALB**
   - AWS ALB Ingress Controller replaces Nginx
   - Cloudflare → ALB → Pod (Nginx is eliminated)
   - SSL termination moves to ALB (or stays at Cloudflare)

6. **Multi-node scaling**
   - Cluster Autoscaler adds/removes EC2 nodes
   - HPA scales pods within nodes
   - Redis migrates to ElastiCache (managed, multi-AZ)

### Architecture evolution

```
[Single VM]                         [Kubernetes]
┌────────────────┐                  ┌────────────────────────┐
│ Cloudflare     │                  │ Cloudflare             │
│ Nginx (docker) │        →         │ ALB (AWS managed)      │
│ API ×2 (docker)│                  │ API ×2-10 (HPA)        │
│ Redis (docker) │                  │ ElastiCache (managed)  │
└────────────────┘                  └────────────────────────┘
  1 VM, manual scale                  Multi-node, auto-scale
```

> **Key insight**: The existing K8s manifests in `docker/k8s/` are already
> compatible with this architecture. The Compose setup is designed to map
> 1:1 to those manifests when you're ready to migrate.


## File Reference

```
docker/
├── Dockerfile              # Multi-stage production image
├── docker-compose.yml      # Production compose with scaling
├── gunicorn.conf.py        # Gunicorn + Uvicorn worker config
├── deploy.sh               # One-command deployment script
├── sysctl-tuning.conf      # Linux kernel parameters
├── ulimits.conf            # File descriptor / process limits
├── nginx/
│   ├── nginx.conf          # Main nginx config (upstream, gzip, perf)
│   └── conf.d/
│       └── default.conf    # Virtual host (proxy, rate limit, security)
└── k8s/                    # Future Kubernetes manifests (existing)
    ├── deployment.yaml
    ├── service.yaml
    ├── hpa.yaml
    ├── ingress.yaml
    ├── configmap.yaml
    ├── namespace.yaml
    └── redis.yaml
```
