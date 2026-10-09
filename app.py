import os
import json
import base64
import threading
import uuid
import requests
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify, Response

BASE_DIR = Path(__file__).resolve().parent
os.chdir(BASE_DIR)

app = Flask(__name__)

# --- токен логов ---
TOKEN_FILE = BASE_DIR / "token.txt"
ENV_TOKEN = os.environ.get("LOGS_TOKEN", "").strip()
RENDER_API_KEY = os.environ.get("RENDER_API_KEY", "").strip()
RENDER_SERVICE_ID = os.environ.get("RENDER_SERVICE_ID", "").strip()

# --- http-прокси ---
PROXY_USER = os.environ.get("PROXY_USER", "").strip()
PROXY_PASS = os.environ.get("PROXY_PASS", "").strip()
UPSTREAM_PROXY_URL = os.environ.get("UPSTREAM_PROXY_URL", "").strip()
UPSTREAM_PROXY_USER = os.environ.get("UPSTREAM_PROXY_USER", "").strip()
UPSTREAM_PROXY_PASS = os.environ.get("UPSTREAM_PROXY_PASS", "").strip()
PROXY_TIMEOUT = int(os.environ.get("PROXY_TIMEOUT", "30"))

PROXY_ENABLED = bool(PROXY_USER and PROXY_PASS and UPSTREAM_PROXY_URL)

# --- лимиты ---
MAX_LOGS = int(os.environ.get("MAX_LOGS", "1000"))
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", "10240"))
# Отдельный лимит для тела ответа (может быть больше)
MAX_RESP_BYTES = int(os.environ.get("MAX_RESP_BYTES", "10240"))

logs = []
lock = threading.Lock()

ALL_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
RENDER_API = "https://api.render.com/v1"


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

    if request.is_json:
        try:
            body_json = json.loads(body_text)
        except Exception:
            body_json = None

    return body_text, body_json, truncated, body_encoding, original_size


def decode_response_body(raw):
    """Декодирует тело ответа. Возвращает (text, encoding, json_obj, truncated, size)."""
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
        # Попробуем распарсить как JSON
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
    with lock:
        logs.append(record)
        if len(logs) > MAX_LOGS:
            logs.pop(0)


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
        return jsonify({"error": err}), 400
    if ENV_TOKEN:
        return jsonify({"error": "token is set via env variable"}), 403
    if token_is_set() and not check_token():
        return jsonify({"error": "unauthorized"}), 401

    save_file_token(new_token)
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


# ==================== СЛУЖЕБНЫЕ ====================

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "time": datetime.now(timezone.utc).isoformat()})


@app.route('/_logs', methods=['GET'])
def view_logs():
    if not check_token():
        return jsonify({"error": "unauthorized"}), 401
    with lock:
        data = list(logs)
    return jsonify({"count": len(data), "logs": data})


@app.route('/_logs/clear', methods=['POST', 'DELETE'])
def clear_logs():
    if not check_token():
        return jsonify({"error": "unauthorized"}), 401
    with lock:
        logs.clear()
    return jsonify({"status": "cleared"})


@app.route('/_logs/delete', methods=['POST'])
def delete_batch():
    if not check_token():
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    ids = data.get("ids")
    if not isinstance(ids, list):
        return jsonify({"error": "ids must be an array"}), 400
    ids_set = set(ids)
    with lock:
        before = len(logs)
        logs[:] = [r for r in logs if r.get("id") not in ids_set]
        removed = before - len(logs)
    return jsonify({"status": "deleted", "removed": removed, "requested": len(ids_set)})


@app.route('/_logs/<log_id>', methods=['DELETE'])
def delete_log(log_id):
    if not check_token():
        return jsonify({"error": "unauthorized"}), 401
    with lock:
        for i, r in enumerate(logs):
            if r.get("id") == log_id:
                logs.pop(i)
                return jsonify({"status": "deleted", "id": log_id})
    return jsonify({"error": "not found"}), 404


# ==================== ПРОКСИ-ОБРАБОТЧИК ====================

def handle_proxy():
    if not check_proxy_auth():
        return Response(
            "Proxy authentication required",
            status=407,
            headers={"Proxy-Authenticate": 'Basic realm="recv-proxy"'},
        )

    target_url = build_target_url()
    if not target_url:
        return Response("Bad Request: cannot determine target host", status=400)

    # --- читаем запрос ---
    body_text, body_json, truncated, body_encoding, body_size = read_body()
    cookies = {k: v for k, v in request.cookies.items()}
    req_headers = dict(request.headers)

    # --- пробрасываем на upstream-прокси ---
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
    except requests.Timeout:
        error = "upstream timeout"
    except requests.RequestException as e:
        error = f"upstream error: {e}"

    # --- логируем ---
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
            "resp_status": None,
            "resp_reason": None,
            "resp_headers": None,
            "resp_body_text": None,
            "resp_body_json": None,
            "resp_body_encoding": None,
            "resp_body_size": 0,
            "resp_body_truncated": False,
            "resp_content_type": None,
            "error": error,
        })

    append_log(record)

    if resp is None:
        return Response(error or "upstream error", status=502 if "error" in (error or "") else 504)

    excluded = {"content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive"}
    resp_headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]
    return Response(resp.content, resp.status_code, resp_headers)


# ==================== ОБЫЧНЫЙ ЛОГГЕР ====================

def handle_log(path):
    body_text, body_json, truncated, body_encoding, body_size = read_body()
    cookies = {k: v for k, v in request.cookies.items()}

    # Формируем ответ (тот JSON, что уйдёт клиенту)
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
        "resp_status": 200,
        "resp_reason": "OK",
        "resp_headers": {"Content-Type": "application/json"},
        "resp_body_text": r_text,
        "resp_body_json": r_json,
        "resp_body_encoding": r_enc,
        "resp_body_size": r_size,
        "resp_body_truncated": r_trunc,
        "resp_content_type": "application/json",
        "error": None,
    }
    append_log(record)

    # id надо положить внутрь ответа
    resp_obj["id"] = record["id"]
    return jsonify(resp_obj), 200


# ==================== ГЛАВНЫЙ МАРШРУТ ====================

@app.route('/', defaults={'path': ''}, methods=ALL_METHODS)
@app.route('/<path:path>', methods=ALL_METHODS)
def catch_all(path):
    if PROXY_ENABLED and is_proxy_request():
        return handle_proxy()
    return handle_log(path)


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)