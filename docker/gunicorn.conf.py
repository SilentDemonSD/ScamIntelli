import os

bind = "0.0.0.0:8000"
backlog = 2048

worker_class = "uvicorn.workers.UvicornWorker"
workers = int(os.getenv("GUNICORN_WORKERS", "4"))
threads = 1

max_requests = int(os.getenv("GUNICORN_MAX_REQUESTS", "2000"))
max_requests_jitter = int(os.getenv("GUNICORN_MAX_REQUESTS_JITTER", "200"))

timeout = int(os.getenv("GUNICORN_TIMEOUT", "120"))
graceful_timeout = 30
keepalive = int(os.getenv("GUNICORN_KEEPALIVE", "10"))

proc_name = "scamintelli"

accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "warning").lower()
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)sus'

preload_app = True
worker_connections = 1000
tmp_upload_dir = "/tmp"


def on_starting(server):
    server.log.info(
        f"ScamIntelli starting: {workers} workers, "
        f"max_requests={max_requests}, timeout={timeout}s"
    )


def post_fork(server, worker):
    server.log.info(f"Worker spawned: PID {worker.pid}")


def worker_exit(server, worker):
    server.log.info(f"Worker exited: PID {worker.pid}")
