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

TOKEN_FILE = BASE_DIR / "token.txt"
ENV_TOKEN = os.environ.get("LOGS_TOKEN", "").strip()
RENDER_API_KEY = os.environ.get("RENDER_API_KEY", "").strip()
RENDER_SERVICE_ID = os.environ.get("RENDER_SERVICE_ID", "").strip()

MAX_LOGS = int(os.environ.get("MAX_LOGS", "1000"))
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", "10240"))

logs = []
lock = threading.Lock()

ALL_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']

RENDER_API = "https://api.render.com/v1"


# ------------------- ВАЛИДАЦИЯ ТОКЕНА -------------------

def validate_token(t):
    if not t or len(t) < 8:
        return False, "token too short (min 8 chars)"
    for ch in t:
        o = ord(ch)
        if o < 0x21 or o > 0x7E:
            return False, "token must contain only printable ASCII characters"
    return True, None


# ------------------- ТОКЕН -------------------

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


# ------------------- ВСПОМОГАТЕЛЬНОЕ -------------------

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


# ------------------- UI -------------------

@app.route('/_ui', methods=['GET'])
def ui():
    html_path = BASE_DIR / 'ui.html'
    return Response(html_path.read_text(encoding='utf-8'), mimetype='text/html')


# ------------------- УПРАВЛЕНИЕ ТОКЕНОМ -------------------

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

    # Если токен уже установлен — требуем текущий
    if token_is_set() and not check_token():
        return jsonify({"error": "unauthorized"}), 401

    save_file_token(new_token)
    return jsonify({"status": "ok", "source": "file"})


@app.route('/_token', methods=['DELETE'])
def remove_token_local():
    if ENV_TOKEN:
        return jsonify({"error": "token is set via env variable and cannot be removed from UI"}), 403

    if not load_file_token():
        return jsonify({"status": "no token"}), 200

    if not check_token():
        return jsonify({"error": "unauthorized"}), 401

    delete_file_token()
    return jsonify({"status": "removed"})


@app.route('/_setup_render_token', methods=['POST'])
def setup_render_token():
    if not render_api_available():
        return jsonify({
            "error": "RENDER_API_KEY and RENDER_SERVICE_ID must be set as env variables on this service"
        }), 503

    # Если токен уже установлен — только с правильной авторизацией
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
        return jsonify({
            "error": "failed to update env var",
            "status": r.status_code,
            "details": r.text[:500],
        }), 502

    deploy_url = f"{RENDER_API}/services/{RENDER_SERVICE_ID}/deploys"
    try:
        d = requests.post(deploy_url, headers=headers,
                          json={"clearCache": "do_not_clear"}, timeout=15)
    except Exception as e:
        return jsonify({
            "warning": "env var set, but deploy request failed",
            "error": str(e),
        }), 502

    if d.status_code not in (200, 201, 202):
        return jsonify({
            "warning": "env var set, but deploy not triggered",
            "status": d.status_code,
            "details": d.text[:500],
        }), 502

    return jsonify({
        "status": "ok",
        "message": "LOGS_TOKEN установлен в Render. Сервис перезапустится через 30-60 секунд.",
        "deploy_id": (d.json() or {}).get("id"),
    })


# ------------------- СЛУЖЕБНЫЕ ЭНДПОИНТЫ -------------------

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
    """Батч-удаление по списку id."""
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


# ------------------- ГЛАВНЫЙ ОБРАБОТЧИК -------------------

@app.route('/', defaults={'path': ''}, methods=ALL_METHODS)
@app.route('/<path:path>', methods=ALL_METHODS)
def catch_all(path):
    body_text, body_json, truncated, body_encoding, body_size = read_body()

    cookies = {k: v for k, v in request.cookies.items()}

    record = {
        "id": uuid.uuid4().hex[:12],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "remote_addr": get_client_ip(),
        "method": request.method,
        "path": request.path,
        "full_url": request.url,
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
    }

    with lock:
        logs.append(record)
        if len(logs) > MAX_LOGS:
            logs.pop(0)

    return jsonify({
        "status": "logged",
        "id": record["id"],
        "path": request.path,
        "method": request.method,
    }), 200


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)