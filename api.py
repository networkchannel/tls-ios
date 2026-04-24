import argparse
import asyncio
import logging
import queue
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from mitmproxy import http, options
from mitmproxy.tools.dump import DumpMaster
from curl_cffi import requests as cffi_requests

log = logging.getLogger("tls_proxy")

BANNER = r"""
 _____ _     ____       ___ ___  ____
|_   _| |   / ___|     |_ _/ _ \/ ___|
  | | | |   \___ \      | | | | \___ \
  | | | |___ ___) |     | | |_| |___) |
  |_| |_____|____/     |___\___/|____/
"""

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade",
}

CONTROL_HEADERS = {"posturl", "postproxy", "postredirect"}

IMPERSONATE = "safari260_ios"

SAFARI_IOS_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1"
)

SAFARI_IOS_DEFAULTS = {
    "Host": None,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "User-Agent": SAFARI_IOS_UA,
    "Connection": "keep-alive",
}

SAFARI_GET_ORDER = [
    "Host",
    "Cookie",
    "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
    "Accept",
    "User-Agent",
    "Accept-Language",
    "Referer",
    "Accept-Encoding",
    "Connection",
]

SAFARI_POST_ORDER = [
    "Host",
    "Cookie",
    "Content-Type",
    "Origin",
    "Content-Length",
    "Accept",
    "User-Agent",
    "Referer",
    "Accept-Language",
    "Accept-Encoding",
    "Connection",
    "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
]


def normalize_proxy(raw: str) -> str:
    if not raw:
        return ""
    raw = raw.strip()
    if "://" not in raw:
        raw = "http://" + raw
    return raw


def build_headers(client_headers: dict, method: str, target_url: str, has_body: bool) -> list:
    incoming = {}
    for k, v in client_headers.items():
        lk = k.lower()
        if lk in HOP_BY_HOP or lk.startswith("proxy-") or lk in CONTROL_HEADERS:
            continue
        if lk == "content-length":
            continue
        incoming[k] = v

    lower_map = {k.lower(): k for k in incoming.keys()}

    def pick(name: str):
        orig = lower_map.get(name.lower())
        if orig is not None:
            return orig, incoming[orig]
        return None, None

    parsed = urlparse(target_url)
    host_value = parsed.netloc
    if "@" in host_value:
        host_value = host_value.split("@", 1)[1]

    merged = {}
    for k, default in SAFARI_IOS_DEFAULTS.items():
        client_k, client_v = pick(k)
        if client_v is not None:
            merged[k] = client_v
        elif k == "Host":
            merged[k] = host_value
        elif default is not None:
            merged[k] = default

    for k, v in incoming.items():
        if k.lower() not in {x.lower() for x in merged.keys()}:
            merged[k] = v

    order = SAFARI_POST_ORDER if method.upper() in ("POST", "PUT", "PATCH") or has_body else SAFARI_GET_ORDER

    ordered = []
    used_lower = set()

    for name in order:
        for existing in list(merged.keys()):
            if existing.lower() == name.lower() and existing.lower() not in used_lower:
                ordered.append((existing, merged[existing]))
                used_lower.add(existing.lower())
                break

    for k, v in merged.items():
        if k.lower() not in used_lower:
            ordered.append((k, v))
            used_lower.add(k.lower())

    return ordered


def headers_to_dict(ordered_pairs):
    d = {}
    for k, v in ordered_pairs:
        d[k] = v
    return d


class SessionPool:
    def __init__(self, size: int):
        self._q: queue.Queue = queue.Queue()
        self._size = size
        self._created = 0
        self._lock = threading.Lock()

    def _new(self) -> cffi_requests.Session:
        return cffi_requests.Session(impersonate=IMPERSONATE)

    def acquire(self) -> cffi_requests.Session:
        try:
            return self._q.get_nowait()
        except queue.Empty:
            with self._lock:
                if self._created < self._size:
                    self._created += 1
                    return self._new()
            return self._q.get()

    def release(self, session: cffi_requests.Session) -> None:
        try:
            self._q.put_nowait(session)
        except queue.Full:
            try:
                session.close()
            except Exception:
                pass


class CurlCffiRelay:
    def __init__(self, pool_size: int, workers: int, timeout: int = 30):
        self.timeout = timeout
        self.pool = SessionPool(pool_size)
        self.executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="relay")

    def _do_request(self, method, url, headers, body, follow, proxies):
        session = self.pool.acquire()
        try:
            return session.request(
                method=method,
                url=url,
                headers=headers,
                data=body,
                timeout=self.timeout,
                allow_redirects=follow,
                proxies=proxies,
                verify=True,
                stream=False,
                default_encoding=None,
            )
        finally:
            self.pool.release(session)

    async def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request

        post_url = req.headers.get("postUrl") or req.headers.get("posturl")
        post_proxy = req.headers.get("postProxy") or req.headers.get("postproxy")
        post_redirect = req.headers.get("postRedirect") or req.headers.get("postredirect")

        if not post_url:
            flow.response = http.Response.make(
                400,
                b'{"error":"missing postUrl header"}',
                {"Content-Type": "application/json"},
            )
            return

        follow = str(post_redirect).strip().lower() == "true" if post_redirect else False
        proxies = None
        if post_proxy:
            p = normalize_proxy(post_proxy)
            proxies = {"http": p, "https": p}

        body = req.raw_content
        has_body = bool(body)

        ordered = build_headers(dict(req.headers), req.method, post_url, has_body)
        headers = headers_to_dict(ordered)

        loop = asyncio.get_running_loop()
        try:
            resp = await loop.run_in_executor(
                self.executor,
                self._do_request,
                req.method, post_url, headers, body, follow, proxies,
            )
        except Exception as e:
            log.warning("upstream error for %s: %s", post_url, e)
            flow.response = http.Response.make(
                502,
                f'{{"error":"upstream","detail":"{str(e)[:200]}"}}'.encode(),
                {"Content-Type": "application/json"},
            )
            return

        out_headers = []
        seen_set_cookie = False
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
            kb = k.encode() if isinstance(k, str) else k
            vb = v.encode() if isinstance(v, str) else v
            out_headers.append((kb, vb))
            if lk == "set-cookie":
                seen_set_cookie = True

        if not seen_set_cookie:
            raw_cookies = getattr(resp, "cookies", None)
            if raw_cookies is not None:
                try:
                    for c in raw_cookies.jar:
                        morsel = f"{c.name}={c.value}"
                        if c.path:
                            morsel += f"; Path={c.path}"
                        if c.domain:
                            morsel += f"; Domain={c.domain}"
                        if c.expires:
                            morsel += f"; Expires={c.expires}"
                        if c.secure:
                            morsel += "; Secure"
                        out_headers.append((b"Set-Cookie", morsel.encode()))
                except Exception:
                    pass

        reason = getattr(resp, "reason", "") or ""
        flow.response = http.Response.make(resp.status_code, resp.content, out_headers)
        if reason:
            try:
                flow.response.reason = reason
            except Exception:
                pass

    def done(self):
        self.executor.shutdown(wait=False)


async def run(port: int, workers: int, pool_size: int):
    opts = options.Options(
        listen_host="127.0.0.1",
        listen_port=port,
        ssl_insecure=False,
        connection_strategy="eager",
    )
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
    relay = CurlCffiRelay(pool_size=pool_size, workers=workers)
    master.addons.add(relay)

    log.info(
        "proxy on http://127.0.0.1:%d | workers=%d | pool=%d | impersonate=%s",
        port, workers, pool_size, IMPERSONATE,
    )

    try:
        await master.run()
    except KeyboardInterrupt:
        pass
    finally:
        relay.done()
        master.shutdown()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--workers", type=int, default=128)
    ap.add_argument("--pool", type=int, default=128)
    ap.add_argument("--log", default="INFO")
    args = ap.parse_args()

    logging.basicConfig(
        level=args.log,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    print(BANNER)

    asyncio.run(run(args.port, args.workers, args.pool))


if __name__ == "__main__":
    main()
