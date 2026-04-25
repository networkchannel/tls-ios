from flask import Flask, request, Response, stream_with_context
from curl_cffi import requests as cffi_requests
import threading
from queue import Queue, Empty

app = Flask(__name__)
IMPERSONATE = "safari260_ios"

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade",
}
CONTROL_HEADERS = {"posturl", "postproxy", "postredirect"}

# ---- Pool de sessions par proxy ----
# curl_cffi Session n'est PAS thread-safe : on garde un pool par config proxy
# et chaque thread emprunte/rend une session.
_pools_lock = threading.Lock()
_session_pools: dict[str, Queue] = {}
POOL_SIZE_PER_PROXY = 50  # ajuster selon le nombre de proxies distincts

def _get_pool(proxy_key: str) -> Queue:
    pool = _session_pools.get(proxy_key)
    if pool is not None:
        return pool
    with _pools_lock:
        pool = _session_pools.get(proxy_key)
        if pool is None:
            pool = Queue(maxsize=POOL_SIZE_PER_PROXY)
            _session_pools[proxy_key] = pool
    return pool

def _make_session(proxies):
    return cffi_requests.Session(impersonate=IMPERSONATE, proxies=proxies)

class SessionLease:
    """Context manager: emprunte une session du pool, la rend après usage."""
    def __init__(self, proxies):
        self.proxies = proxies
        self.proxy_key = "" if not proxies else proxies.get("https", "")
        self.pool = _get_pool(self.proxy_key)
        self.session = None

    def __enter__(self):
        try:
            self.session = self.pool.get_nowait()
        except Empty:
            self.session = _make_session(self.proxies)
        return self.session

    def __exit__(self, exc_type, exc, tb):
        if self.session is None:
            return
        # Si erreur réseau, on jette la session par sécurité
        if exc_type is not None:
            try:
                self.session.close()
            except Exception:
                pass
            return
        try:
            self.pool.put_nowait(self.session)
        except Exception:
            try:
                self.session.close()
            except Exception:
                pass

def normalize_proxy(raw: str) -> str:
    if not raw:
        return ""
    raw = raw.strip()
    if "://" not in raw:
        raw = "http://" + raw
    return raw

@app.route("/", defaults={"path": ""}, methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
@app.route("/<path:path>", methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
def proxy(path):
    post_url = request.headers.get("postUrl") or request.headers.get("posturl")
    post_proxy = request.headers.get("postProxy") or request.headers.get("postproxy")
    post_redirect = request.headers.get("postRedirect") or request.headers.get("postredirect")

    if not post_url and request.method in ("GET", "HEAD") and path == "":
        return Response("OK", status=200, content_type="text/plain")
    if not post_url:
        return Response('{"error":"missing postUrl header"}', status=400,
                        content_type="application/json")

    forward_headers = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in HOP_BY_HOP or lk in CONTROL_HEADERS:
            continue
        if lk in ("content-length", "host"):
            continue
        forward_headers[k] = v

    proxies = None
    if post_proxy:
        p = normalize_proxy(post_proxy)
        proxies = {"http": p, "https": p}

    follow = str(post_redirect).strip().lower() == "true" if post_redirect else False
    body = request.get_data() or None

    try:
        with SessionLease(proxies) as session:
            resp = session.request(
                method=request.method,
                url=post_url,
                headers=forward_headers,
                data=body,
                timeout=30,
                allow_redirects=follow,
                verify=True,
                stream=True,  # important : ne pas tout charger en RAM
            )

            out_headers = []
            headers_iter = (
                resp.headers.multi_items()
                if hasattr(resp.headers, "multi_items")
                else resp.headers.items()
            )
            for k, v in headers_iter:
                lk = k.lower()
                if lk in HOP_BY_HOP or lk in ("content-encoding", "content-length"):
                    continue
                out_headers.append((k, v))

            def generate():
                try:
                    for chunk in resp.iter_content(chunk_size=64 * 1024):
                        if chunk:
                            yield chunk
                finally:
                    resp.close()

            return Response(
                stream_with_context(generate()),
                status=resp.status_code,
                headers=out_headers,
            )
    except Exception as e:
        return Response(
            f'{{"error":"upstream","detail":"{str(e)[:200]}"}}',
            status=502,
            content_type="application/json",
        )

if __name__ == "__main__":
    from waitress import serve
    print(f"TLS Proxy Waitress sur http://0.0.0.0:8080 | impersonate={IMPERSONATE}")
    serve(
        app,
        host="0.0.0.0",
        port=8080,
        threads=200,           # 200 workers
        connection_limit=1000, # backlog
        channel_timeout=120,
        cleanup_interval=30,
        asyncore_use_poll=True,
    )
