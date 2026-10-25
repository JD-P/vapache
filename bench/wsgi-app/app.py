"""Minimal WSGI fixture used by bench/app_bench.py."""


def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    body = ('{"ok":true,"runtime":"gunicorn","path":"%s"}\n' % path).encode()
    start_response(
        "200 OK",
        [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
        ],
    )
    return [body]
