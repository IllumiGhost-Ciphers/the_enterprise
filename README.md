#!/usr/bin/env python3
# ============================================================
# Enterprise Honeypot Compound — Multi-Protocol Deception
# Safe simulations, adaptive personas, structured logging.
# ============================================================

import asyncio
import logging
import json
import random
import time
import signal
import hashlib
import os
from logging.handlers import RotatingFileHandler, SysLogHandler

# Optional Kafka forwarding (graceful degrade if missing)
try:
    from kafka import KafkaProducer  # pip install kafka-python
    KAFKA_AVAILABLE = True
except Exception:
    KAFKA_AVAILABLE = False

# -----------------------------
# Config
# -----------------------------
CONFIG = {
    "ports": {
        "ssh": 2222,        # faux-SSH line protocol
        "http": 8080,       # HTTP server
        "redis": 6379,      # redis-like
        "mysql": 3306,      # banner only
        "mqtt": 1883        # mqtt-like
    },
    "personas": [
        "ubuntu-apache", "windows-rdp", "k8s-api",
        "s3-bucket", "mysql-node", "redis-node"
    ],
    "log_file": "honeypot.log",
    "quarantine_dir": "quarantine",
    "kafka": {
        "enabled": False,
        "bootstrap_servers": "localhost:9092",
        "topic": "honeypot-events"
    },
    "syslog": {
        "enabled": False,
        "address": ("localhost", 514)
    }
}

os.makedirs(CONFIG["quarantine_dir"], exist_ok=True)

# -----------------------------
# Logging
# -----------------------------
logger = logging.getLogger("honeypot")
logger.setLevel(logging.INFO)
logger.propagate = False

file_handler = RotatingFileHandler(CONFIG["log_file"], maxBytes=10_000_000, backupCount=5)
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(file_handler)

console = logging.StreamHandler()
console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(console)

syslog_handler = None
if CONFIG["syslog"]["enabled"]:
    syslog_handler = SysLogHandler(address=CONFIG["syslog"]["address"])
    syslog_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(syslog_handler)

kafka_producer = None
if CONFIG["kafka"]["enabled"] and KAFKA_AVAILABLE:
    kafka_producer = KafkaProducer(
        bootstrap_servers=CONFIG["kafka"]["bootstrap_servers"],
        value_serializer=lambda v: json.dumps(v).encode("utf-8")
    )

def emit(event: dict):
    logger.info(json.dumps(event))
    if kafka_producer:
        try:
            kafka_producer.send(CONFIG["kafka"]["topic"], event)
        except Exception as e:
            logger.error(json.dumps({"event": "kafka_error", "error": str(e)}))

def persona():
    return random.choice(CONFIG["personas"])

def jitter(min_s=0.05, max_s=0.35):
    d = random.uniform(min_s, max_s)
    time.sleep(d)
    return d

# -----------------------------
# Faux SSH (line-based)
# -----------------------------
async def ssh_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info('peername')
    p = persona()
    emit({"service": "ssh", "event": "connect", "peer": peer, "persona": p})
    # banner
    writer.write(b"SSH-2.0-OpenSSH_8.9p1\r\n")
    await writer.drain()

    prompts = [b"login: ", b"password: "]
    creds = {}
    for label in ["user", "pass"]:
        writer.write(prompts[0] if label=="user" else prompts[1])
        await writer.drain()
        line = await reader.readline()
        creds[label] = line.decode(errors="ignore").strip()
        prompts.pop(0)
    emit({"service": "ssh", "event": "creds", "peer": peer, "data": creds})

    # fake shell
    writer.write(b"Welcome to glyph-sh.\r\n$ ")
    await writer.drain()
    while True:
        cmd = await reader.readline()
        if not cmd:
            break
        c = cmd.decode(errors="ignore").strip()
        emit({"service": "ssh", "event": "cmd", "peer": peer, "cmd": c})
        if c.lower() in ("exit", "quit", "logout"):
            writer.write(b"Session closed.\r\n")
            await writer.drain()
            break
        # respond with glyph echoes
        writer.write(f"* glyph::{p}::ack::{hashlib.sha256(c.encode()).hexdigest()[:8]}\r\n$ ".encode())
        await writer.drain()

    writer.close()
    await writer.wait_closed()
    emit({"service": "ssh", "event": "disconnect", "peer": peer})

# -----------------------------
# HTTP server (aiohttp)
# -----------------------------
from aiohttp import web  # pip install aiohttp

async def http_index(request):
    p = persona()
    emit({"service": "http", "event": "hit", "path": "/", "peer": request.remote, "persona": p})
    return web.Response(text=f"""
<html>
<head><title>Admin</title></head>
<body>
<h1>Glyph Admin</h1>
<p>persona: {p}</p>
<p>try /login, /api/status, POST /upload</p>
</body></html>
""", content_type="text/html")

async def http_login(request):
    emit({"service": "http", "event": "hit", "path": "/login", "peer": request.remote})
    return web.Response(text="Login page (simulated). Submit JSON to POST /api/login", content_type="text/plain")

async def http_api_status(request):
    emit({"service": "http", "event": "api_status", "peer": request.remote})
    return web.json_response({"status": "ok", "persona": persona(), "ts": time.time()})

async def http_api_login(request):
    data = await request.json(content_type=None)
    emit({"service": "http", "event": "login_attempt", "peer": request.remote, "data": data})
    return web.json_response({"ok": True, "message": "Recorded"})

async def http_upload(request):
    reader = await request.multipart()
    field = await reader.next()
    if not field or field.name != 'file':
        return web.json_response({"ok": False, "error": "file field required"}, status=400)

    filename = field.filename or f"upload_{int(time.time())}"
    path = os.path.join(CONFIG["quarantine_dir"], filename)
    size = 0
    with open(path, "wb") as f:
        while True:
            chunk = await field.read_chunk()
            if not chunk:
                break
            size += len(chunk)
            f.write(chunk)

    sha = hashlib.sha256(open(path, "rb").read()).hexdigest()
    emit({"service": "http", "event": "quarantined", "file": filename, "size": size, "sha256": sha})
    return web.json_response({"ok": True, "file": filename, "size": size, "sha256": sha})

def build_http_app():
    app = web.Application()
    app.router.add_get("/", http_index)
    app.router.add_get("/login", http_login)
    app.router.add_get("/api/status", http_api_status)
    app.router.add_post("/api/login", http_api_login)
    app.router.add_post("/upload", http_upload)
    return app

# -----------------------------
# Redis-like (RESP minimal)
# -----------------------------
async def redis_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info('peername')
    emit({"service": "redis", "event": "connect", "peer": peer})
    kv = {}

    async def respond(msg: bytes):
        writer.write(msg)
        await writer.drain()

    while True:
        line = await reader.readline()
        if not line:
            break
        text = line.decode(errors="ignore").strip()
        emit({"service": "redis", "event": "recv", "peer": peer, "raw": text})
        # very naive parse: PING -> +PONG
        if text.upper().endswith("PING"):
            await respond(b"+PONG\r\n")
        elif text.upper().startswith("SET"):
            parts = text.split()
            if len(parts) >= 3:
                kv[parts[1]] = " ".join(parts[2:])
                await respond(b"+OK\r\n")
            else:
                await respond(b"-ERR wrong args\r\n")
        elif text.upper().startswith("GET"):
            parts = text.split()
            val = kv.get(parts[1], "")
            await respond(f"${len(val)}\r\n{val}\r\n".encode())
        else:
            await respond(b"-ERR unknown\r\n")

    writer.close()
    await writer.wait_closed()
    emit({"service": "redis", "event": "disconnect", "peer": peer})

# -----------------------------
# MySQL banner (no handshake)
# -----------------------------
async def mysql_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info('peername')
    p = persona()
    emit({"service": "mysql", "event": "connect", "peer": peer, "persona": p})
    writer.write(b"\x0a5.7.31-0ubuntu0.18.04.1\x00")  # fake handshake banner string
    await writer.drain()
    await asyncio.sleep(random.uniform(0.2, 1.2))
    writer.close()
    await writer.wait_closed()
    emit({"service": "mysql", "event": "disconnect", "peer": peer})

# -----------------------------
# MQTT-like (very minimal)
# -----------------------------
async def mqtt_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info('peername')
    emit({"service": "mqtt", "event": "connect", "peer": peer})
    # read a few bytes and send CONNACK-like reply
    try:
        data = await reader.read(8)
        emit({"service": "mqtt", "event": "recv", "peer": peer, "bytes": len(data)})
        writer.write(b"\x20\x02\x00\x00")  # CONNACK success (simulated)
        await writer.drain()
    except Exception as e:
        emit({"service": "mqtt", "event": "error", "error": str(e)})

    writer.close()
    await writer.wait_closed()
    emit({"service": "mqtt", "event": "disconnect", "peer": peer})

# -----------------------------
# Orchestrator
# -----------------------------
async def start_server(coro, port, name):
    server = await asyncio.start_server(coro, host="0.0.0.0", port=port)
    emit({"service": name, "event": "listening", "port": port})
    return server

async def start_http(port):
    app = build_http_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    emit({"service": "http", "event": "listening", "port": port})
    return runner  # keep reference for graceful shutdown

async def main():
    emit({"event": "boot", "msg": "honeypot starting"})
    loop = asyncio.get_event_loop()

    # Graceful shutdown
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    servers = []
    runners = []

    # Start protocols
    servers.append(await start_server(ssh_handler, CONFIG["ports"]["ssh"], "ssh"))
    runners.append(await start_http(CONFIG["ports"]["http"]))
    servers.append(await start_server(redis_handler, CONFIG["ports"]["redis"], "redis"))
    servers.append(await start_server(mysql_handler, CONFIG["ports"]["mysql"], "mysql"))
    servers.append(await start_server(mqtt_handler, CONFIG["ports"]["mqtt"], "mqtt"))

    emit({"event": "ready", "services": list(CONFIG["ports"].items())})

    # Heartbeat
    async def pulse():
        while not stop.is_set():
            emit({"event": "pulse", "ts": time.time()})
            await asyncio.sleep(5)

    pulse_task = asyncio.create_task(pulse())

    await stop.wait()
    emit({"event": "shutdown", "msg": "stopping services"})

    # Cleanup
    pulse_task.cancel()
    for s in servers:
        s.close()
        await s.wait_closed()
    for r in runners:
        await r.cleanup()

    emit({"event": "down", "msg": "honeypot stopped"})

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
