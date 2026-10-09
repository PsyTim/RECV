import os
import json
import base64
import struct
import socket
import select
import threading
import uuid
import random
import sqlite3
import logging
import requests
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, request, jsonify, Response

BASE_DIR = Path(__file__).resolve().parent
os.chdir(BASE_DIR)

# ==================== ЛОГИРОВАНИЕ ====================

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    force=True,
)
log = logging.getLogger("smsproxy")

logging.getLogger("werkzeug").setLevel(logging.WARNING)

app = Flask(__name__)

# --- токен логов ---
TOKEN_FILE = BASE_DIR / "token.txt"
ENV_TOKEN = os.environ.get("LOGS_TOKEN", "").strip()
RENDER_API_KEY = os.environ.get("RENDER_API_KEY", "").strip()
RENDER_SERVICE_ID = os.environ.get("RENDER_SERVICE_ID", "").strip()

# --- БД ---
DB_FILE = BASE_DIR / "logs.db"
LOGS_FILE = BASE_DIR / "logs.json"

# --- http-прокси ---
PROXY_USER = os.environ.get("PROXY_USER", "").strip()
PROXY_PASS = os.environ.get("PROXY_PASS", "").strip()
UPSTREAM_PROXY_URL = os.environ.get("UPSTREAM_PROXY_URL", "").strip()
UPSTREAM_PROXY_USER = os.environ.get("UPSTREAM_PROXY_USER", "").strip()
UPSTREAM_PROXY_PASS = os.environ.get("UPSTREAM_PROXY_PASS", "").strip()
PROXY_TIMEOUT = int(os.environ.get("PROXY_TIMEOUT", "30"))

PROXY_ENABLED = bool(PROXY_USER and PROXY_PASS and UPSTREAM_PROXY_URL)

# --- SOCKS5 ---
SOCKS_USER = os.environ.get("SOCKS_USER", "").strip()
SOCKS_PASS = os.environ.get("SOCKS_PASS", "").strip()
SOCKS_PORT = int(os.environ.get("SOCKS_PORT", "1080"))
SOCKS_ENABLED = bool(SOCKS_USER and SOCKS_PASS and UPSTREAM_PROXY_URL)

# --- телефон и AID ---
COUNTER_FILE = BASE_DIR / "counter.txt"
AID_UNIT_SECONDS = float(os.environ.get("AID_UNIT_SECONDS", "180"))
AID_RAND_MIN = int(os.environ.get("AID_RAND_MIN", "3"))
AID_RAND_MAX = int(os.environ.get("AID_RAND_MAX", "7"))

aid_lock = threading.Lock()

MAX_LOGS = int(os.environ.get("MAX_LOGS", "1000"))
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", "10240"))
MAX_RESP_BYTES = int(os.environ.get("MAX_RESP_BYTES", "10240"))

ALL_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
RENDER_API = "https://api.render.com/v1"

QUIET_PREFIXES = ('/_logs', '/_ui', '/health', '/_token', '/_phone', '/favicon.ico')

SUSPICIOUS_PATTERNS = (
    '/connect',
    '/autodiscover', '/ecp', '/owa', '/mapi', '/rpc',
    '/wp-admin', '/wp-login', '/wp-content', '/xmlrpc.php',
    '/phpmyadmin', '/pma', '/mysql',
    '/.env', '/.git', '/.aws', '/.ssh',
    '/sourcedb/', '/cgi-bin/', '/scripts/',
    '/admin', '/manager', '/console',
    '/vendor/', '/config/',
)
SUSPICIOUS_SUFFIXES = ('.php', '.asp', '.aspx', '.jsp', '.cgi', '.env', '.git')


# ==================== SQLITE ====================

db_lock = threading.Lock()
_db_conn = None


def init_db():
    global _db_conn
    _db_conn = sqlite3.connect(str(DB_FILE), check_same_thread=False)
    _db_conn.row_factory = sqlite3.Row
    _db_conn.execute("PRAGMA journal_mode=WAL")
    _db_conn.execute("PRAGMA synchronous=NORMAL")
    _db_conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            remote_addr TEXT,
            method TEXT,
            path TEXT,
            full_url TEXT,
            target_url TEXT,
            proxy INTEGER DEFAULT 0,
            phone_request INTEGER DEFAULT 0,
            phone_served INTEGER DEFAULT 0,
            query_params TEXT,
            headers TEXT,
            cookies TEXT,
            content_type TEXT,
            body_text TEXT,
            body_json TEXT,
            body_encoding TEXT,
            body_size INTEGER,
            body_truncated INTEGER DEFAULT 0,
            form TEXT,
            resp_status INTEGER,
            resp_reason TEXT,
            resp_headers TEXT,
            resp_body_text TEXT,
            resp_body_json TEXT,
            resp_body_encoding TEXT,
            resp_body_size INTEGER,
            resp_body_truncated INTEGER DEFAULT 0,
            resp_content_type TEXT,
            error TEXT
        )
    """)
    _db_conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
    _db_conn.execute("""
        CREATE TABLE IF NOT EXISTS kv (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    _db_conn.commit()

    log.info("DB initialised at %s", DB_FILE)
    try:
        cur = _db_conn.execute("SELECT COUNT(*) FROM logs")
        log.info("DB: logs count = %d", cur.fetchone()[0])
        cur = _db_conn.execute("SELECT key, value FROM kv")
        kv_rows = [(r["key"], r["value"]) for r in cur.fetchall()]
        log.info("DB: kv contents = %r", kv_rows)
    except Exception as e:
        log.warning("DB diagnostics failed: %s", e)


def kv_get(key):
    with db_lock:
        cur = _db_conn.execute("SELECT value FROM kv WHERE key = ?", (key,))
        row = cur.fetchone()
        return row["value"] if row else None


def kv_set(key, value):
    with db_lock:
        if value is None:
            _db_conn.execute("DELETE FROM kv WHERE key = ?", (key,))
            log.info("KV SET: %s = <deleted>", key)
        else:
            _db_conn.execute(
                "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)",
                (key, str(value)),
            )
            log.info("KV SET: %s = %r", key, str(value))
        _db_conn.commit()


def _to_json(x):
    if x is None:
        return None
    try:
        return json.dumps(x, ensure_ascii=False)
    except Exception:
        return None


def _from_json(s):
    if s is None or s == "":
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def _insert_log_sql(record):
    _db_conn.execute("""
        INSERT OR REPLACE INTO logs (
            id, timestamp, remote_addr, method, path, full_url, target_url,
            proxy, phone_request, phone_served,
            query_params, headers, cookies, content_type,
            body_text, body_json, body_encoding, body_size, body_truncated, form,
            resp_status, resp_reason, resp_headers,
            resp_body_text, resp_body_json, resp_body_encoding,
            resp_body_size, resp_body_truncated, resp_content_type, error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        record.get("id"),
        record.get("timestamp"),
        record.get("remote_addr"),
        record.get("method"),
        record.get("path"),
        record.get("full_url"),
        record.get("target_url"),
        1 if record.get("proxy") else 0,
        1 if record.get("phone_request") else 0,
        1 if record.get("phone_served") else 0,
        _to_json(record.get("query_params")),
        _to_json(record.get("headers")),
        _to_json(record.get("cookies")),
        record.get("content_type"),
        record.get("body_text"),
        _to_json(record.get("body_json")),
        record.get("body_encoding"),
        record.get("body_size"),
        1 if record.get("body_truncated") else 0,
        _to_json(record.get("form")),
        record.get("resp_status"),
        record.get("resp_reason"),
        _to_json(record.get("resp_headers")),
        record.get("resp_body_text"),
        _to_json(record.get("resp_body_json")),
        record.get("resp_body_encoding"),
        record.get("resp_body_size"),
        1 if record.get("resp_body_truncated") else 0,
        record.get("resp_content_type"),
        record.get("error"),
    ))


def _row_to_dict(row):
    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "remote_addr": row["remote_addr"],
        "method": row["method"],
        "path": row["path"],
        "full_url": row["full_url"],
        "target_url": row["target_url"],
        "proxy": bool(row["proxy"]),
        "phone_request": bool(row["phone_request"]),
        "phone_served": bool(row["phone_served"]),
        "query_params": _from_json(row["query_params"]) or {},
        "headers": _from_json(row["headers"]) or {},
        "cookies": _from_json(row["cookies"]) or {},
        "content_type": row["content_type"],
        "body_text": row["body_text"],
        "body_json": _from_json(row["body_json"]),
        "body_encoding": row["body_encoding"],
        "body_size": row["body_size"],
        "body_truncated": bool(row["body_truncated"]),
        "form": _from_json(row["form"]) or {},
        "resp_status": row["resp_status"],
        "resp_reason": row["resp_reason"],
        "resp_headers": _from_json(row["resp_headers"]),
        "resp_body_text": row["resp_body_text"],
        "resp_body_json": _from_json(row["resp_body_json"]),
        "resp_body_encoding": row["resp_body_encoding"],
        "resp_body_size": row["resp_body_size"],
        "resp_body_truncated": bool(row["resp_body_truncated"]),
        "resp_content_type": row["resp_content_type"],
        "error": row["error"],
    }


def db_insert_log(record):
    with db_lock:
        _insert_log_sql(record)
        _db_conn.execute("""
            DELETE FROM logs WHERE seq NOT IN (
                SELECT seq FROM logs ORDER BY seq DESC LIMIT ?
            )
        """, (MAX_LOGS,))
        _db_conn.commit()


def db_get_logs():
    with db_lock:
        cur = _db_conn.execute("SELECT * FROM logs ORDER BY seq ASC")
        return [_row_to_dict(r) for r in cur.fetchall()]


def db_clear_logs():
    with db_lock:
        _db_conn.execute("DELETE FROM logs")
        _db_conn.commit()


def db_delete_log(log_id):
    with db_lock:
        cur = _db_conn.execute("DELETE FROM logs WHERE id = ?", (log_id,))
        _db_conn.commit()
        return cur.rowcount > 0


def db_delete_batch(ids):
    if not ids:
        return 0
    with db_lock:
        placeholders = ",".join("?" * len(ids))
        cur = _db_conn.execute(
            f"DELETE FROM logs WHERE id IN ({placeholders})",
            list(ids),
        )
        _db_conn.commit()
        return cur.rowcount


def migrate_from_json():
    if not LOGS_FILE.exists():
        return
    try:
        cur = _db_conn.execute("SELECT COUNT(*) FROM logs")
        if cur.fetchone()[0] > 0:
            return
        data = json.loads(LOGS_FILE.read_text(encoding='utf-8'))
        if not isinstance(data, list):
            return
        with db_lock:
            for record in data:
                if isinstance(record, dict) and record.get("id"):
                    _insert_log_sql(record)
            _db_conn.commit()
        try:
            LOGS_FILE.rename(LOGS_FILE.with_suffix('.json.migrated'))
            log.info("Migrated %d logs from logs.json", len(data))
        except Exception:
            pass
    except Exception as e:
        log.warning("Migration from logs.json failed: %s", e)


# ==================== ТОКЕН ====================

def validate_token(t):
    if not t or len(t) < 8:
        return False, "token too short (min 8 chars)"
    for ch in t:
        o = ord(ch)
        if o < 0x21 or o > 0x7E:
            return False, "token must contain only printable ASCII characters"
    return True, None


def load_file_token():
    try:
        if TOKEN_FILE.exists():
            return TOKEN_FILE.read_text(encoding='utf-8').strip()
    except Exception:
        pass
    return ""


def save_file_token(token):
    TOKEN_FILE.write_text(token, encoding='utf-8')
    try:
        os.chmod(TOKEN_FILE, 0o600)
    except Exception:
        pass


def delete_file_token():
    try:
        if TOKEN_FILE.exists():
            TOKEN_FILE.unlink()
    except Exception:
        pass


def get_active_token():
    if ENV_TOKEN:
        return ENV_TOKEN, "env"
    file_tok = load_file_token()
    if file_tok:
        return file_tok, "file"
    return "", None


def check_token():
    active, _ = get_active_token()
    if not active:
        return True
    return request.headers.get("Authorization", "") == f"Bearer {active}"


def token_is_set():
    active, _ = get_active_token()
    return bool(active)


def render_api_available():
    return bool(RENDER_API_KEY and RENDER_SERVICE_ID)


# ==================== AID-СЧЁТЧИК ====================

def _read_counter_file():
    try:
        if COUNTER_FILE.exists():
            text = COUNTER_FILE.read_text(encoding='utf-8').strip()
            if ':' in text:
                ts_str, aid_str = text.split(':', 1)
                return int(ts_str.strip()), int(aid_str.strip())
    except Exception:
        pass
    return None, None


def _write_counter_file(ts, aid):
    try:
        COUNTER_FILE.write_text(f"{int(ts)}:{int(aid)}", encoding='utf-8')
    except Exception:
        pass


def _new_aid_counter():
    ts = int(datetime.now(timezone.utc).timestamp())
    aid = random.randint(100000, 999999)
    _write_counter_file(ts, aid)
    log.info("AID counter initialised: %d (ts=%d)", aid, ts)
    return ts, aid


def load_aid_counter():
    ts, aid = _read_counter_file()
    if ts is None or aid is None:
        return _new_aid_counter()
    return ts, aid


def next_aid():
    with aid_lock:
        ts, aid = load_aid_counter()
        now = int(datetime.now(timezone.utc).timestamp())
        delta = max(0, now - ts)
        multiplier = random.randint(AID_RAND_MIN, AID_RAND_MAX)
        incr = 1 + int((delta / AID_UNIT_SECONDS) * multiplier)
        new_aid = aid + incr
        _write_counter_file(now, new_aid)
        log.info("AID: %d -> %d (delta=%ds, rand=%d, incr=%d)",
                 aid, new_aid, delta, multiplier, incr)
        return new_aid


# ==================== ПРОКСИ: АВТОРИЗАЦИЯ ====================

def parse_proxy_auth():
    h = request.headers.get("Proxy-Authorization")
    if not h:
        return None
    if not h.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(h[6:].strip()).decode('utf-8')
    except Exception:
        return None
    if ':' not in decoded:
        return None
    return tuple(decoded.split(':', 1))


def check_proxy_auth():
    creds = parse_proxy_auth()
    if not creds:
        return False
    u, p = creds
    return u == PROXY_USER and p == PROXY_PASS


def is_proxy_request():
    return bool(request.headers.get("Proxy-Authorization"))


def build_target_url():
    path = request.path or "/"
    qs = request.query_string.decode('utf-8', errors='replace')
    if path.startswith("http://") or path.startswith("https://"):
        target = path
    else:
        host = request.headers.get("Host", "")
        if not host:
            return None
        target = f"http://{host}{path}"
    if qs:
        target += ("&" if "?" in target else "?") + qs
    return target


# ==================== ВСПОМОГАТЕЛЬНОЕ ====================

def get_client_ip():
    xff = request.headers.get('X-Forwarded-For')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr


def read_body():
    raw = request.get_data(cache=True, as_text=False)
    if not raw:
        return None, None, False, None, 0

    original_size = len(raw)
    truncated = False
    if original_size > MAX_BODY_BYTES:
        raw = raw[:MAX_BODY_BYTES]
        truncated = True

    body_text = None
    body_encoding = None
    body_json = None

    try:
        body_text = raw.decode('utf-8')
        body_encoding = 'utf-8'
    except UnicodeDecodeError:
        body_text = base64.b64encode(raw).decode('ascii')
        body_encoding = 'base64'

    if body_text:
        stripped = body_text.lstrip()
        if stripped.startswith('{') or stripped.startswith('['):
            try:
                body_json = json.loads(body_text)
            except Exception:
                body_json = None

    return body_text, body_json, truncated, body_encoding, original_size


def decode_response_body(raw):
    if not raw:
        return None, None, None, False, 0

    original_size = len(raw)
    truncated = False
    if original_size > MAX_RESP_BYTES:
        raw = raw[:MAX_RESP_BYTES]
        truncated = True

    text = None
    encoding = None
    json_obj = None

    try:
        text = raw.decode('utf-8')
        encoding = 'utf-8'
        stripped = text.lstrip()
        if stripped.startswith('{') or stripped.startswith('['):
            try:
                json_obj = json.loads(text)
            except Exception:
                json_obj = None
    except UnicodeDecodeError:
        text = base64.b64encode(raw).decode('ascii')
        encoding = 'base64'

    return text, encoding, json_obj, truncated, original_size


def append_log(record):
    db_insert_log(record)


def should_quiet_log(path):
    return path.startswith(QUIET_PREFIXES)


def is_suspicious(path):
    p = path.lower()
    if any(p.startswith(x) for x in SUSPICIOUS_PATTERNS):
        return True
    if any(p.endswith(x) for x in SUSPICIOUS_SUFFIXES):
        return True
    return False


# ==================== SOCKS5 SERVER ====================

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _upstream_tunnel(host, port):
    """Открыть raw TCP-туннель к host:port через upstream HTTP-прокси (CONNECT)."""
    up = urlparse(UPSTREAM_PROXY_URL)
    up_host = up.hostname
    up_port = up.port or 80
    s = socket.create_connection((up_host, up_port), timeout=15)

    req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
    if UPSTREAM_PROXY_USER:
        creds = base64.b64encode(
            f"{UPSTREAM_PROXY_USER}:{UPSTREAM_PROXY_PASS}".encode('utf-8')
        ).decode('ascii')
        req += f"Proxy-Authorization: Basic {creds}\r\n"
    req += "Proxy-Connection: Keep-Alive\r\n\r\n"
    s.sendall(req.encode('utf-8'))

    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = s.recv(4096)
        if not chunk:
            s.close()
            raise IOError("upstream closed during CONNECT")
        resp += chunk
        if len(resp) > 16384:
            s.close()
            raise IOError("upstream CONNECT response too large")

    first_line = resp.split(b"\r\n", 1)[0].decode('latin-1', 'replace')
    if " 200 " not in first_line and not first_line.startswith("HTTP/1.1 200") \
            and not first_line.startswith("HTTP/1.0 200"):
        s.close()
        raise IOError(f"upstream CONNECT failed: {first_line}")
    return s


def _pipe(a, b):
    """Двунаправленная перекачка байтов между двумя сокетами."""
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 300)
            if not r:
                break
            for s in r:
                other = b if s is a else a
                data = s.recv(65536)
                if not data:
                    return
                other.sendall(data)
    except Exception:
        pass
    finally:
        for s in (a, b):
            try:
                s.close()
            except Exception:
                pass


def _select_socks5_auth(client, methods, client_ip="?"):
    """Согласовать метод аутентификации. Возвращает True или None."""
    if SOCKS_USER:
        if 0x02 not in methods:
            client.sendall(b"\x05\xff")
            log.warning(
                "SOCKS5: client %s offered methods=%s, but we require username/password (0x02)",
                client_ip, [hex(m) for m in methods]
            )
            return None
        client.sendall(b"\x05\x02")
        hdr = _recv_exact(client, 2)
        if not hdr or hdr[0] != 0x01:
            log.warning("SOCKS5: %s bad auth subnegotiation header: %r", client_ip, hdr)
            return None
        ulen = hdr[1]
        uname = _recv_exact(client, ulen)
        plen_b = _recv_exact(client, 1)
        if uname is None or plen_b is None:
            log.warning("SOCKS5: %s short read on credentials", client_ip)
            return None
        plen = plen_b[0]
        passwd = _recv_exact(client, plen)
        if passwd is None:
            log.warning("SOCKS5: %s short read on password", client_ip)
            return None
        u = uname.decode('utf-8', 'replace')
        p = passwd.decode('utf-8', 'replace')
        expected_pass_len = len(SOCKS_PASS)
        ok = (u == SOCKS_USER and p == SOCKS_PASS)
        log.info(
            "SOCKS5 auth attempt from %s: user=%r, pass_len=%d (expected %d), match=%s",
            client_ip, u, len(p), expected_pass_len, ok
        )
        if ok:
            client.sendall(b"\x01\x00")
            return True
        client.sendall(b"\x01\x01")
        return None
    else:
        if 0x00 not in methods:
            client.sendall(b"\x05\xff")
            log.warning(
                "SOCKS5: client %s offered methods=%s, but we require no-auth (0x00)",
                client_ip, [hex(m) for m in methods]
            )
            return None
        client.sendall(b"\x05\x00")
        return True


def _socks5_handle_client(client, addr):
    client_ip = addr[0] if addr else "?"
    try:
        client.settimeout(30)

        # --- greeting ---
        hdr = _recv_exact(client, 2)
        if not hdr or hdr[0] != 0x05:
            log.debug("SOCKS5: %s not a SOCKS5 greeting: %r", client_ip, hdr)
            return
        nmethods = hdr[1]
        methods = _recv_exact(client, nmethods)
        if methods is None:
            log.debug("SOCKS5 %s: short read on methods", client_ip)
            return

        if _select_socks5_auth(client, methods, client_ip) is None:
            log.warning("SOCKS5 auth failed from %s", client_ip)
            return

        log.info("SOCKS5 %s: auth OK, waiting for CONNECT request", client_ip)

        # --- request ---
        try:
            rhdr = _recv_exact(client, 4)
        except socket.timeout:
            log.warning("SOCKS5 %s: timeout while waiting for CONNECT after auth (peer did not send)", client_ip)
            return
        except (ConnectionResetError, BrokenPipeError) as e:
            log.info("SOCKS5 %s: peer reset connection after auth (%s)", client_ip, type(e).__name__)
            return

        if rhdr is None:
            log.info("SOCKS5 %s: peer closed connection after auth WITHOUT sending CONNECT", client_ip)
            return

        log.info("SOCKS5 %s: request bytes = %s", client_ip, rhdr.hex())
        ver, cmd, rsv, atyp = rhdr

        if ver != 0x05:
            log.warning("SOCKS5 %s: bad VER in request: 0x%02x", client_ip, ver)
            client.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        if cmd != 0x01:
            log.warning("SOCKS5 %s: unsupported CMD 0x%02x (only CONNECT=0x01 is supported)", client_ip, cmd)
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        if atyp == 0x01:                    # IPv4
            raw = _recv_exact(client, 4)
            if raw is None:
                log.info("SOCKS5 %s: short read on IPv4 address", client_ip)
                return
            host = socket.inet_ntoa(raw)
        elif atyp == 0x03:                  # domain
            ln_b = _recv_exact(client, 1)
            if ln_b is None:
                log.info("SOCKS5 %s: short read on domain length", client_ip)
                return
            ln = ln_b[0]
            raw = _recv_exact(client, ln)
            if raw is None:
                log.info("SOCKS5 %s: short read on domain", client_ip)
                return
            host = raw.decode('utf-8', 'replace')
        elif atyp == 0x04:                  # IPv6
            raw = _recv_exact(client, 16)
            if raw is None:
                log.info("SOCKS5 %s: short read on IPv6 address", client_ip)
                return
            host = socket.inet_ntop(socket.AF_INET6, raw)
        else:
            log.warning("SOCKS5 %s: unsupported ATYP 0x%02x", client_ip, atyp)
            client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        port_b = _recv_exact(client, 2)
        if port_b is None:
            log.info("SOCKS5 %s: short read on port", client_ip)
            return
        port = struct.unpack("!H", port_b)[0]

        log.info("SOCKS5 %s: CONNECT request to %s:%d, opening upstream tunnel...",
                 client_ip, host, port)

        # --- open tunnel via upstream ---
        try:
            remote = _upstream_tunnel(host, port)
        except Exception as e:
            log.warning("SOCKS5 CONNECT %s:%d from %s failed: %s", host, port, client_ip, e)
            client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        # success reply
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        log.info("SOCKS5 CONNECT %s:%d from %s — tunnel established", host, port, client_ip)

        client.settimeout(None)
        remote.settimeout(None)
        _pipe(client, remote)

    except socket.timeout:
        log.warning("SOCKS5 %s: socket timeout", client_ip)
    except (ConnectionResetError, BrokenPipeError) as e:
        log.info("SOCKS5 %s: connection error: %s", client_ip, type(e).__name__)
    except Exception as e:
        log.warning("SOCKS5 client %s error: %s: %s", client_ip, type(e).__name__, e)
    finally:
        try:
            client.close()
        except Exception:
            pass


def start_socks5_server():
    if not SOCKS_ENABLED:
        log.info("SOCKS5 disabled (need SOCKS_USER, SOCKS_PASS, UPSTREAM_PROXY_URL)")
        return

    def loop():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("0.0.0.0", SOCKS_PORT))
        except Exception as e:
            log.error("SOCKS5 bind 0.0.0.0:%d failed: %s", SOCKS_PORT, e)
            return
        srv.listen(64)
        log.info("SOCKS5 listening on 0.0.0.0:%d (upstream=%s)", SOCKS_PORT, UPSTREAM_PROXY_URL)

        while True:
            try:
                client, addr = srv.accept()
                threading.Thread(
                    target=_socks5_handle_client,
                    args=(client, addr),
                    daemon=True,
                ).start()
            except Exception as e:
                log.error("SOCKS5 accept error: %s", e)

    threading.Thread(target=loop, daemon=True).start()


# ==================== UI ====================

@app.route('/_ui', methods=['GET'])
def ui():
    html_path = BASE_DIR / 'ui.html'
    return Response(html_path.read_text(encoding='utf-8'), mimetype='text/html')


# ==================== УПРАВЛЕНИЕ ТОКЕНОМ ====================

@app.route('/_token/status', methods=['GET'])
def token_status():
    active, source = get_active_token()
    file_tok = load_file_token()
    return jsonify({
        "required": bool(active),
        "source": source,
        "env_locked": bool(ENV_TOKEN),
        "render_api_available": render_api_available(),
        "can_set_local": (not ENV_TOKEN),
        "can_delete_local": (not ENV_TOKEN) and bool(file_tok),
    })


@app.route('/_token', methods=['POST'])
def set_token_local():
    data = request.get_json(silent=True) or {}
    new_token = (data.get("token") or "").strip()

    ok, err = validate_token(new_token)
    if not ok:
        log.warning("TOKEN set rejected: %s", err)
        return jsonify({"error": err}), 400
    if ENV_TOKEN:
        return jsonify({"error": "token is set via env variable"}), 403
    if token_is_set() and not check_token():
        log.warning("TOKEN set rejected: unauthorized from %s", request.remote_addr)
        return jsonify({"error": "unauthorized"}), 401

    save_file_token(new_token)
    log.info("TOKEN saved to file")
    return jsonify({"status": "ok", "source": "file"})


@app.route('/_token', methods=['DELETE'])
def remove_token_local():
    if ENV_TOKEN:
        return jsonify({"error": "token is set via env variable"}), 403
    if not load_file_token():
        return jsonify({"status": "no token"}), 200
    if not check_token():
        return jsonify({"error": "unauthorized"}), 401
    delete_file_token()
    log.info("TOKEN removed")
    return jsonify({"status": "removed"})


@app.route('/_setup_render_token', methods=['POST'])
def setup_render_token():
    if not render_api_available():
        return jsonify({"error": "RENDER_API_KEY and RENDER_SERVICE_ID must be set"}), 503
    if token_is_set() and not check_token():
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    new_token = (data.get("token") or "").strip()
    ok, err = validate_token(new_token)
    if not ok:
        return jsonify({"error": err}), 400

    headers = {
        "Authorization": f"Bearer {RENDER_API_KEY}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    url = f"{RENDER_API}/services/{RENDER_SERVICE_ID}/env-vars/LOGS_TOKEN"
    try:
        r = requests.put(url, headers=headers, json={"value": new_token}, timeout=15)
    except Exception as e:
        log.error("RENDER API PUT failed: %s", e)
        return jsonify({"error": f"request to Render failed: {e}"}), 502
    if r.status_code not in (200, 201):
        return jsonify({"error": "failed to update env var", "status": r.status_code, "details": r.text[:500]}), 502

    deploy_url = f"{RENDER_API}/services/{RENDER_SERVICE_ID}/deploys"
    try:
        d = requests.post(deploy_url, headers=headers, json={"clearCache": "do_not_clear"}, timeout=15)
    except Exception as e:
        return jsonify({"warning": "env var set, but deploy failed", "error": str(e)}), 502
    if d.status_code not in (200, 201, 202):
        return jsonify({"warning": "env var set, but deploy not triggered", "status": d.status_code, "details": d.text[:500]}), 502

    return jsonify({
        "status": "ok",
        "message": "LOGS_TOKEN установлен. Сервис перезапустится через 30-60 секунд.",
        "deploy_id": (d.json() or {}).get("id"),
    })


# ==================== ТЕЛЕФОН (SQLite kv) ====================

PHONE_KV_KEY = "phone"


def get_current_phone():
    return kv_get(PHONE_KV_KEY)


def set_current_phone(phone):
    kv_set(PHONE_KV_KEY, phone if phone else None)


def consume_phone():
    with db_lock:
        cur = _db_conn.execute("SELECT value FROM kv WHERE key = ?", (PHONE_KV_KEY,))
        row = cur.fetchone()
        phone = row["value"] if row else None
        if phone:
            _db_conn.execute("DELETE FROM kv WHERE key = ?", (PHONE_KV_KEY,))
            _db_conn.commit()
            log.info("PHONE consumed from kv: %r", phone)
        else:
            log.info("PHONE consume: kv empty")
    return phone


@app.route('/_phone', methods=['GET', 'POST', 'DELETE'])
def phone_endpoint():
    if not check_token():
        log.warning("PHONE %s unauthorized from %s", request.method, request.remote_addr)
        return jsonify({"error": "unauthorized"}), 401

    if request.method == 'GET':
        phone = get_current_phone()
        log.debug("PHONE GET -> %r", phone)
        return jsonify({"phone": phone})

    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        new_phone = (data.get("phone") or "").strip()
        log.info("PHONE POST <- %r from %s", new_phone, request.remote_addr)
        set_current_phone(new_phone)
        saved = get_current_phone()
        log.info("PHONE saved: %r", saved)
        return jsonify({"status": "ok", "phone": saved})

    log.info("PHONE DELETE from %s", request.remote_addr)
    set_current_phone(None)
    return jsonify({"status": "cleared"})


# ==================== СЛУЖЕБНЫЕ ====================

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "time": datetime.now(timezone.utc).isoformat()})


@app.route('/_logs', methods=['GET'])
def view_logs():
    if not check_token():
        return jsonify({"error": "unauthorized"}), 401
    data = db_get_logs()
    return jsonify({"count": len(data), "logs": data})


@app.route('/_logs/clear', methods=['POST', 'DELETE'])
def clear_logs():
    if not check_token():
        return jsonify({"error": "unauthorized"}), 401
    db_clear_logs()
    log.info("LOGS cleared by %s", request.remote_addr)
    return jsonify({"status": "cleared"})


@app.route('/_logs/delete', methods=['POST'])
def delete_batch():
    if not check_token():
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    ids = data.get("ids")
    if not isinstance(ids, list):
        return jsonify({"error": "ids must be an array"}), 400
    removed = db_delete_batch(ids)
    log.info("LOGS batch delete: requested=%d removed=%d", len(set(ids)), removed)
    return jsonify({"status": "deleted", "removed": removed, "requested": len(set(ids))})


@app.route('/_logs/<log_id>', methods=['DELETE'])
def delete_log(log_id):
    if not check_token():
        return jsonify({"error": "unauthorized"}), 401
    if db_delete_log(log_id):
        log.info("LOG deleted: %s", log_id)
        return jsonify({"status": "deleted", "id": log_id})
    return jsonify({"error": "not found"}), 404


# ==================== HTTP ПРОКСИ ====================

def handle_proxy():
    if not check_proxy_auth():
        log.warning("PROXY auth failed from %s", request.remote_addr)
        return Response(
            "Proxy authentication required",
            status=407,
            headers={"Proxy-Authenticate": 'Basic realm="recv-proxy"'},
        )

    target_url = build_target_url()
    if not target_url:
        return Response("Bad Request: cannot determine target host", status=400)

    body_text, body_json, truncated, body_encoding, body_size = read_body()
    cookies = {k: v for k, v in request.cookies.items()}
    req_headers = dict(request.headers)

    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in (
            "host", "proxy-authorization", "proxy-connection",
            "connection", "content-length", "transfer-encoding",
            "keep-alive", "upgrade",
        )
    }

    proxies = {"http": UPSTREAM_PROXY_URL, "https": UPSTREAM_PROXY_URL}
    upstream_auth = None
    if UPSTREAM_PROXY_USER:
        upstream_auth = requests.auth.HTTPProxyAuth(UPSTREAM_PROXY_USER, UPSTREAM_PROXY_PASS)

    error = None
    resp = None
    try:
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=forward_headers,
            data=request.get_data(),
            proxies=proxies,
            auth=upstream_auth,
            timeout=PROXY_TIMEOUT,
            allow_redirects=False,
        )
        log.info("PROXY %s %s -> %s", request.method, target_url, resp.status_code)
    except requests.Timeout:
        error = "upstream timeout"
        log.error("PROXY %s %s timeout", request.method, target_url)
    except requests.RequestException as e:
        error = f"upstream error: {e}"
        log.error("PROXY %s %s error: %s", request.method, target_url, e)

    record = {
        "id": uuid.uuid4().hex[:12],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "remote_addr": get_client_ip(),
        "method": request.method,
        "path": request.path,
        "full_url": target_url,
        "target_url": target_url,
        "proxy": True,
        "query_params": request.args.to_dict(flat=False),
        "headers": req_headers,
        "cookies": cookies,
        "content_type": request.content_type,
        "body_text": body_text,
        "body_json": body_json,
        "body_encoding": body_encoding,
        "body_size": body_size,
        "body_truncated": truncated,
        "form": request.form.to_dict(flat=False) if request.form else {},
    }

    if resp is not None:
        r_text, r_enc, r_json, r_trunc, r_size = decode_response_body(resp.content)
        record.update({
            "resp_status": resp.status_code,
            "resp_reason": resp.reason,
            "resp_headers": dict(resp.headers),
            "resp_body_text": r_text,
            "resp_body_json": r_json,
            "resp_body_encoding": r_enc,
            "resp_body_size": r_size,
            "resp_body_truncated": r_trunc,
            "resp_content_type": resp.headers.get("Content-Type"),
            "error": None,
        })
    else:
        record.update({
            "resp_status": None, "resp_reason": None, "resp_headers": None,
            "resp_body_text": None, "resp_body_json": None, "resp_body_encoding": None,
            "resp_body_size": 0, "resp_body_truncated": False, "resp_content_type": None,
            "error": error,
        })

    append_log(record)

    if resp is None:
        return Response(error or "upstream error", status=502 if "error" in (error or "") else 504)

    excluded = {"content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive"}
    resp_headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]
    return Response(resp.content, resp.status_code, resp_headers)


# ==================== ОБЫЧНЫЙ ЛОГГЕР + getNumber ====================

def is_phone_getter_request(body_json):
    actions = None

    if isinstance(body_json, dict):
        actions = body_json.get("action")

    if actions is None:
        q_actions = request.args.getlist("action")
        if q_actions:
            actions = q_actions

    if actions is None:
        return False
    if isinstance(actions, str):
        actions = [actions]
    if not isinstance(actions, list):
        return False
    return "getNumber" in actions


def handle_log(path):
    body_text, body_json, truncated, body_encoding, body_size = read_body()
    cookies = {k: v for k, v in request.cookies.items()}

    if is_phone_getter_request(body_json):
        log.info("GETNUMBER request from %s at %s",
                 request.remote_addr, request.full_path.rstrip('?'))
        phone = consume_phone()
        if phone:
            aid = next_aid()
            resp_text = f"ACCESS_NUMBER:{aid}:{phone}"
            phone_served = True
            log.info("GETNUMBER response: %s", resp_text)
        else:
            resp_text = "-"
            phone_served = False
            log.info("GETNUMBER response: - (no phone)")

        resp_body = resp_text.encode('utf-8')
        r_text, r_enc, r_json, r_trunc, r_size = decode_response_body(resp_body)

        record = {
            "id": uuid.uuid4().hex[:12],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remote_addr": get_client_ip(),
            "method": request.method,
            "path": request.path,
            "full_url": request.url,
            "proxy": False,
            "phone_request": True,
            "phone_served": phone_served,
            "query_params": request.args.to_dict(flat=False),
            "headers": dict(request.headers),
            "cookies": cookies,
            "content_type": request.content_type,
            "body_text": body_text,
            "body_json": body_json,
            "body_encoding": body_encoding,
            "body_size": body_size,
            "body_truncated": truncated,
            "form": request.form.to_dict(flat=False) if request.form else {},
            "resp_status": 200, "resp_reason": "OK",
            "resp_headers": {"Content-Type": "text/plain"},
            "resp_body_text": r_text, "resp_body_json": None,
            "resp_body_encoding": r_enc, "resp_body_size": r_size,
            "resp_body_truncated": r_trunc, "resp_content_type": "text/plain",
            "error": None,
        }
        append_log(record)
        return Response(resp_text, mimetype="text/plain")

    resp_obj = {
        "status": "logged",
        "path": request.path,
        "method": request.method,
    }
    resp_json_str = json.dumps(resp_obj)
    r_text, r_enc, r_json, r_trunc, r_size = decode_response_body(resp_json_str.encode('utf-8'))

    record = {
        "id": uuid.uuid4().hex[:12],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "remote_addr": get_client_ip(),
        "method": request.method,
        "path": request.path,
        "full_url": request.url,
        "proxy": False,
        "phone_request": False,
        "phone_served": False,
        "query_params": request.args.to_dict(flat=False),
        "headers": dict(request.headers),
        "cookies": cookies,
        "content_type": request.content_type,
        "body_text": body_text,
        "body_json": body_json,
        "body_encoding": body_encoding,
        "body_size": body_size,
        "body_truncated": truncated,
        "form": request.form.to_dict(flat=False) if request.form else {},
        "resp_status": 200, "resp_reason": "OK",
        "resp_headers": {"Content-Type": "application/json"},
        "resp_body_text": r_text, "resp_body_json": r_json,
        "resp_body_encoding": r_enc, "resp_body_size": r_size,
        "resp_body_truncated": r_trunc, "resp_content_type": "application/json",
        "error": None,
    }
    append_log(record)

    resp_obj["id"] = record["id"]
    return jsonify(resp_obj), 200


# ==================== ГЛАВНЫЙ МАРШРУТ ====================

@app.route('/', defaults={'path': ''}, methods=ALL_METHODS)
@app.route('/<path:path>', methods=ALL_METHODS)
def catch_all(path):
    if is_suspicious(request.path):
        log.warning("BLOCKED suspicious %s from %s", request.path, request.remote_addr)
        return Response("Not Found", status=404)

    is_proxy = PROXY_ENABLED and is_proxy_request()

    if not should_quiet_log(request.path):
        log.info("REQ %s %s from %s proxy=%s",
                 request.method, request.full_path.rstrip('?'),
                 request.remote_addr, is_proxy)

    if is_proxy:
        return handle_proxy()
    return handle_log(path)


# ==================== ОШИБКИ ====================

@app.errorhandler(Exception)
def handle_exception(e):
    log.exception("Unhandled exception on %s %s", request.method, request.path)
    return jsonify({"error": "internal server error", "type": type(e).__name__}), 500


# ==================== ИНИЦИАЛИЗАЦИЯ ====================

init_db()
migrate_from_json()
load_aid_counter()
log.info("App initialised. PROXY_ENABLED=%s, SOCKS_ENABLED=%s, token_required=%s",
         PROXY_ENABLED, SOCKS_ENABLED, token_is_set())

start_socks5_server()


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)