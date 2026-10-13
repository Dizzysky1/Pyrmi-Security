from http.server import BaseHTTPRequestHandler
import hashlib
import hmac

_A = "e4107c7bf9078b613d4fa3047ec937c8dae554aeb0092d4253dccaca6667fe78"
_C = "5b0accf8fea4970a27a4979d8fe1"


def _open(k):
    s = hashlib.sha256(b"msg:" + k).digest()
    return bytes(a ^ b for a, b in zip(bytes.fromhex(_C), s)).decode()


class handler(BaseHTTPRequestHandler):
    def _nf(self):
        b = b"The page could not be found\n\nNOT_FOUND\n"
        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("X-Vercel-Error", "NOT_FOUND")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b)

    def do_PUT(self):
        k = (self.headers.get("X-Knock") or "").encode()
        h = hashlib.sha256(b"auth:" + k).hexdigest()
        if not k or not hmac.compare_digest(h, _A):
            return self._nf()
        b = (_open(k) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    do_GET = do_POST = do_HEAD = do_DELETE = do_PATCH = do_OPTIONS = _nf
