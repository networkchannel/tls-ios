from flask import Flask, request, Response
from curl_cffi import requests as cffi_requests

app = Flask(__name__)

IMPERSONATE = "safari260_ios"

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade",
}

CONTROL_HEADERS = {"posturl", "postproxy", "postredirect"}


def normalize_proxy(raw: str) -> str:
    if not raw:
        return ""
    raw = raw.strip()
    if "://" not in raw:
        raw = "http://" + raw
    return raw


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def proxy(path):
    # Lire les headers de contrôle
    post_url = request.headers.get("postUrl") or request.headers.get("posturl")
    post_proxy = request.headers.get("postProxy") or request.headers.get("postproxy")
    post_redirect = request.headers.get("postRedirect") or request.headers.get("postredirect")

    if not post_url:
        return Response(
            '{"error":"missing postUrl header"}',
            status=400,
            content_type="application/json",
        )

    # Forward TES headers tels quels (sauf hop-by-hop et headers de contrôle)
    forward_headers = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in HOP_BY_HOP or lk in CONTROL_HEADERS:
            continue
        if lk == "content-length":
            continue
        if lk == "host":
            continue  # sera recalculé par curl_cffi selon l'URL cible
        forward_headers[k] = v

    # Proxy upstream
    proxies = None
    if post_proxy:
        p = normalize_proxy(post_proxy)
        proxies = {"http": p, "https": p}

    # Redirect
    follow = str(post_redirect).strip().lower() == "true" if post_redirect else False

    # Body
    body = request.get_data() or None

    # Créer une session fraîche avec l'impersonate et le proxy
    session = cffi_requests.Session(
        impersonate=IMPERSONATE,
        proxies=proxies,
    )

    try:
        resp = session.request(
            method=request.method,
            url=post_url,
            headers=forward_headers,
            data=body,
            timeout=30,
            allow_redirects=follow,
            verify=True,
        )
    except Exception as e:
        return Response(
            f'{{"error":"upstream","detail":"{str(e)[:200]}"}}',
            status=502,
            content_type="application/json",
        )
    finally:
        session.close()

    # Construire la réponse avec les headers de la cible tels quels
    out_headers = []
    headers_iter = (
        resp.headers.multi_items()
        if hasattr(resp.headers, "multi_items")
        else resp.headers.items()
    )
    for k, v in headers_iter:
        lk = k.lower()
        if lk in HOP_BY_HOP:
            continue
        if lk in ("content-encoding", "content-length"):
            continue
        out_headers.append((k, v))

    return Response(
        resp.content,
        status=resp.status_code,
        headers=out_headers,
    )


if __name__ == "__main__":
    print(f"TLS Proxy Flask sur http://0.0.0.0:8080 | impersonate={IMPERSONATE}")
    app.run(host="0.0.0.0", port=8080, threaded=True, debug=False)
