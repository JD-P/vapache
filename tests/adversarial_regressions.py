#!/usr/bin/env python3
"""End-to-end regressions for the pass-2/pass-3 findings (F23-F38).

The suite starts a fresh vapached instance in a temporary tree and exercises
the exploit shapes from findings.md: terminal rewrite/proxy authorization,
cache generations and CGI PATH_INFO, relative and capture-only regex aliases,
autoindex links, negated/environment Require providers, IndexIgnore,
DirectorySlash Off, UnsafePrefixStat re-rooting, header-selected cache
entries, .htaccess RequestHeader, and CGI REMOTE_USER/AUTH_TYPE.

Usage:
    cargo build --release -p vapached
    python3 tests/adversarial_regressions.py -v
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import os
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VAPACHED = Path(os.environ.get("VAPACHED", ROOT / "target" / "release" / "vapached"))


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class Backend(BaseHTTPRequestHandler):
    hits = 0
    last_headers: dict[str, str] = {}

    def do_GET(self):
        Backend.hits += 1
        Backend.last_headers = dict(self.headers)
        body = b"WALLET-BACKEND-SECRET\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def request(port: int, path: str, headers: dict[str, str] | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path, headers=headers or {})
    response = conn.getresponse()
    body = response.read()
    status = response.status
    response_headers = dict(response.getheaders())
    conn.close()
    return status, response_headers, body


class F23ToF38Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-adversarial-", dir="/tmp/opencode"))
        cls.www = cls.base / "www"
        cls.logs = cls.base / "logs"
        cls.cache = cls.base / "cache"
        for directory in (
            cls.www,
            cls.www / "cgi",
            cls.www / "admin",
            cls.www / "list",
            cls.www / "env",
            cls.www / "indexignore",
            cls.www / "indexignore-main",
            cls.www / "tenant",
            cls.www / "reqheader",
            cls.www / "cgiauth",
            cls.www / "private-cgi",
            cls.www / "public-cgi",
            cls.www / "limit-cgi",
            cls.www / "exprtest",
            cls.logs,
            cls.cache,
            cls.base / "private" / "sub",
        ):
            directory.mkdir(parents=True, exist_ok=True)
        cls.www.chmod(0o755)
        cls.base.chmod(0o755)
        cls.logs.chmod(0o777)
        cls.cache.chmod(0o777)

        (cls.www / "hello.txt").write_text("hello\n")
        (cls.www / "secret.txt").write_text("WALLET-ENV-SECRET\n")
        (cls.www / "admin" / "wallet.dat").write_text("WALLET-DIR-SECRET\n")
        (cls.www / "list" / "public.txt").write_text("public\n")
        # Hostile filenames that used to become executable/scheme-relative hrefs.
        (cls.www / "list" / "javascript:alert(1)").write_text("x\n")
        (cls.www / "list" / "data:text,boom").write_text("x\n")
        (cls.www / "indexignore" / "public.txt").write_text("public\n")
        (cls.www / "indexignore" / "wallet.secret").write_text("secret\n")
        (cls.www / "indexignore" / ".htaccess").write_text("IndexIgnore *.secret\n")
        (cls.www / "indexignore-main" / "public.txt").write_text("public\n")
        (cls.www / "indexignore-main" / "wallet.secret").write_text("secret\n")
        (cls.www / "env" / "secret.txt").write_text("WALLET-SETENVIF-SECRET\n")
        (cls.www / "env" / "allowed.txt").write_text("WALLET-SETENV-ALLOWED\n")
        (cls.www / "env" / "negated-env.txt").write_text("WALLET-NEGATED-ENV\n")
        (cls.www / "env" / "negated-expr.txt").write_text("WALLET-NEGATED-EXPR\n")
        (cls.www / "env" / ".htaccess").write_text(
            "SetEnv STATIC_ALLOW yes\n"
            "SetEnvIf X-Block yes BLOCK=1\n"
            '<Files "secret.txt">\n'
            '    Require expr "%{ENV:BLOCK} == \'\'"\n'
            "</Files>\n"
            '<Files "allowed.txt">\n'
            "    Require env STATIC_ALLOW\n"
            "</Files>\n"
        )
        (cls.www / "cgi" / "wallet.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n'\n"
            "printf 'Cache-Control: max-age=600\\r\\n\\r\\n'\n"
            "printf 'WALLET-RELOAD-SECRET\\n'\n"
        )
        (cls.www / "cgi" / "wallet.cgi").chmod(0o755)
        (cls.base / "private" / ".htaccess").write_text("Require all denied\n")
        (cls.base / "private" / "wallet.dat").write_text(
            "WALLET-SINGLE-FILE-ALIAS-SECRET\n"
        )
        (cls.base / "private" / "sub" / "secret.txt").write_text(
            "WALLET-RELALIAS-SECRET\n"
        )
        # F39: a single-file Alias/ScriptAlias must use the target basename for
        # handler dispatch and must read the target directory's .htaccess.
        (cls.www / "cgi" / "alias-run.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'WALLET-ALIAS-CGI-EXECUTED\\n'\n"
        )
        (cls.www / "cgi" / "alias-run.cgi").chmod(0o755)
        # F40: Options -ExecCGI inside <Limit> must take effect.
        (cls.www / "limit-cgi" / "script.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'WALLET-LIMIT-EXECCGI-BYPASS\\n'\n"
        )
        (cls.www / "limit-cgi" / "script.cgi").chmod(0o755)
        # F45: expression file tests must not observe paths outside docroot.
        (cls.www / "exprtest" / "secret.txt").write_text(
            "WALLET-EXPR-CONFINEMENT\n"
        )
        (cls.www / "exprtest" / ".htaccess").write_text(
            "Require expr \"-f '/etc/passwd'\"\n"
        )
        # F41: a public symlink to a script in a denied directory.
        (cls.www / "private-cgi" / "admin.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'WALLET-PRIVATE-CGI-SECRET\\n'\n"
        )
        (cls.www / "private-cgi" / "admin.cgi").chmod(0o755)
        (cls.www / "private-cgi" / "secret.php").write_text(
            "<?php /* WALLET-PRIVATE-PHP-SECRET */ ?>\n"
        )
        (cls.www / "public-cgi" / "link.cgi").symlink_to(
            "../private-cgi/admin.cgi"
        )
        (cls.www / "public-cgi" / "link.php").symlink_to(
            "../private-cgi/secret.php"
        )

        # F31: an absolute target outside ServerRoot.  The capture-only alias
        # must fail instead of re-rooting at the file's parent directory.
        cls.alias_dir = Path(
            tempfile.mkdtemp(prefix="vapache-alias-escape-", dir="/tmp/opencode")
        )
        cls.alias_secret = cls.alias_dir / "secret.txt"
        cls.alias_secret.write_text("WALLET-ALIAS-SECRET\n")
        # F32: a file under ServerRoot but outside DocumentRoot.
        (cls.base / "rewrite-secret.txt").write_text("WALLET-REWRITE-SECRET\n")

        # F34: cacheable, header-selected representation.
        (cls.www / "tenant" / "cacheme.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n'\n"
            "printf 'Cache-Control: max-age=600\\r\\n\\r\\n'\n"
            "printf 'WALLET-TENANT-CACHE\\n'\n"
        )
        (cls.www / "tenant" / "cacheme.cgi").chmod(0o755)
        # F36: a request-mutating directive that used to be silently ignored.
        (cls.www / "reqheader" / "secret.txt").write_text("WALLET-REQHEADER-SECRET\n")
        (cls.www / "reqheader" / ".htaccess").write_text(
            "RequestHeader set X-Block yes\n"
            '<Files "secret.txt">\n'
            "    Require expr \"%{HTTP:X-Block} != 'yes'\"\n"
            "</Files>\n"
        )
        # F38: authenticated CGI identity.
        (cls.www / "cgiauth" / "who.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'REMOTE_USER=[%s]\\n' \"$REMOTE_USER\"\n"
            "printf 'AUTH_TYPE=[%s]\\n' \"$AUTH_TYPE\"\n"
        )
        (cls.www / "cgiauth" / "who.cgi").chmod(0o755)
        digest = base64.b64encode(hashlib.sha1(b"alicepw").digest()).decode()
        (cls.base / ".htpasswd").write_text(f"alice:{{SHA}}{digest}\n")
        (cls.base / ".htpasswd").chmod(0o644)

        cls.backend = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
        cls.backend_port = cls.backend.server_address[1]
        threading.Thread(target=cls.backend.serve_forever, daemon=True).start()
        cls.port = free_port()
        cls.config = cls.base / "vp.conf"
        cls.write_config()
        cls.proc = subprocess.Popen(
            [str(VAPACHED), "-f", str(cls.config), "-DFOREGROUND"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        output = b""
        if cls.proc.stdout:
            output = cls.proc.stdout.read()
        raise RuntimeError(f"vapached failed to start:\n{output.decode(errors='replace')}")

    @classmethod
    def write_config(cls, extra: str = ""):
        cls.config.write_text(
            f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
Timeout 30
DocumentRoot "{cls.www}"
CacheRoot "{cls.cache}"
CacheEnable disk /
CacheHeader On
CacheDefaultExpire 600
AddHandler cgi-script .cgi
DirectoryIndex index.html
<Directory "{cls.www}">
    AllowOverride All
    Options +Indexes +ExecCGI +FollowSymLinks
    Require all granted
</Directory>
<Directory "{cls.www}/indexignore-main">
    Options +Indexes
    IndexIgnore *.secret
    Require all granted
</Directory>
<Directory "{cls.www}/admin">
    Options +Indexes
    DirectorySlash Off
    Require all granted
</Directory>
<Directory "{cls.base}/private">
    AllowOverride All
    Require all granted
</Directory>
<Directory "{cls.www}/private-cgi">
    Require all denied
</Directory>
<Directory "{cls.www}/limit-cgi">
    <Limit GET>
        Options -ExecCGI
    </Limit>
</Directory>
<Files "admin.cgi">
    Require all denied
</Files>
ProxyPassMatch ^/(.*\\.php)$ "unix:{cls.base}/fcgi.sock|fcgi://localhost{cls.www}/"
Alias /wallet "{cls.base}/private/wallet.dat"
Alias /run "{cls.www}/cgi/alias-run.cgi"
ScriptAlias /exec "{cls.www}/cgi/alias-run.cgi"

RewriteEngine On
RewriteRule ^/admin-rewrite$ /front [L]
RewriteRule ^/front$ http://127.0.0.1:{cls.backend_port}/secret [P]
RewriteRule ^/admin-redirect$ /redirect-front [L]
RewriteRule ^/redirect-front$ /hello.txt [R=302,L]
RewriteRule ^/unsafe/(.*)$ "{cls.base}/$1" [L,UnsafePrefixStat]
RewriteRule ^/env-rewrite$ /hello.txt [L,E=BLOCK:1]
RewriteRule ^/query-rewrite$ /hello.txt?new=1 [L]

<Location "/admin-rewrite">
    Require all denied
</Location>
<Location "/admin-redirect">
    Require all denied
</Location>
<Location "/admin/">
    Require all denied
</Location>
<Location "/env/negated-env.txt">
    <RequireAll>
        Require all granted
        Require not env BLOCK
    </RequireAll>
</Location>
<Location "/env/negated-expr.txt">
    <RequireAll>
        Require all granted
        Require not expr "%{{HTTP:X-Block}} == 'yes'"
    </RequireAll>
</Location>
<Location "/env/secret.txt">
    <RequireAll>
        Require all granted
        Require not env BLOCK
    </RequireAll>
</Location>
<Location "/env-rewrite">
    Require expr "%{{ENV:BLOCK}} == ''"
</Location>
<Location "/query-rewrite">
    <RequireAll>
        Require all granted
        Require expr "%{{QUERY_STRING}} == 'orig=1'"
    </RequireAll>
</Location>
<Location "/tenant/">
    <RequireAll>
        Require all granted
        Require expr "%{{HTTP:X-Tenant}} == 'alpha'"
    </RequireAll>
</Location>
<Location "/cgiauth/">
    AuthType Basic
    AuthName "CGI Realm"
    AuthUserFile "{cls.base}/.htpasswd"
    Require valid-user
</Location>
SetEnvIf X-Block yes BLOCK=1
AliasMatch "^/rel/(.*)$" "private/$1"
AliasMatch "^/escape(.*)$" "$1"

# A cacheable CGI route used by the F24 reload test.  The deny is appended by
# reload_with_wallet_deny().
"""
            + extra
        )

    @classmethod
    def reload_with_wallet_deny(cls):
        cls.write_config('<Files "wallet.cgi">\n    Require all denied\n</Files>\n')
        os.kill(cls.proc.pid, signal.SIGHUP)
        deadline = time.time() + 10
        while time.time() < deadline:
            status, _, _ = request(cls.port, "/cgi/wallet.cgi")
            if status == 403:
                return
            time.sleep(0.1)
        raise AssertionError("reload did not apply the <Files> deny")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "proc", None) and cls.proc.poll() is None:
            try:
                os.killpg(os.getpgid(cls.proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(cls.proc.pid), signal.SIGKILL)
        if getattr(cls, "backend", None):
            cls.backend.shutdown()
            cls.backend.server_close()
        if os.environ.get("KEEP_TEST_TREE") != "1":
            shutil.rmtree(cls.base, ignore_errors=True)
            alias_dir = getattr(cls, "alias_dir", None)
            if alias_dir is not None:
                shutil.rmtree(alias_dir, ignore_errors=True)

    def test_f23_rewrite_then_proxy_keeps_original_authorization(self):
        status, _, body = request(self.port, "/admin-rewrite")
        self.assertEqual(status, 403, body[:200])

    def test_f23_rewrite_then_redirect_keeps_original_authorization(self):
        status, _, body = request(self.port, "/admin-redirect")
        self.assertEqual(status, 403, body[:200])

    def test_f24_reload_and_path_info_cache_are_bound_to_script(self):
        status, _, body = request(self.port, "/cgi/wallet.cgi/foo")
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"WALLET-RELOAD-SECRET", body)
        type(self).reload_with_wallet_deny()
        for path in ("/cgi/wallet.cgi", "/cgi/wallet.cgi/foo"):
            status, _, body = request(self.port, path)
            self.assertEqual(status, 403, f"{path}: {body[:200]}")
            self.assertNotIn(b"WALLET-RELOAD-SECRET", body)

    def test_f25_relative_regex_alias_reads_target_htaccess(self):
        status, _, body = request(self.port, "/rel/sub/secret.txt")
        self.assertEqual(status, 403, body[:200])

    def test_f26_autoindex_never_emits_scheme_urls(self):
        status, _, body = request(self.port, "/list/")
        self.assertEqual(status, 200)
        text = body.decode("utf-8", "replace")
        self.assertIn('href="./javascript:alert(1)"', text)
        self.assertNotIn('href="javascript:', text)
        self.assertNotIn('href="data:', text)

    def test_f27_negated_env_and_expr_operands_are_bound_correctly(self):
        status, _, body = request(self.port, "/env/negated-env.txt")
        self.assertEqual(status, 200, body[:200])
        status, _, body = request(
            self.port, "/env/negated-env.txt", {"X-Block": "yes"}
        )
        self.assertEqual(status, 403, body[:200])
        status, _, body = request(
            self.port, "/env/negated-expr.txt", {"X-Block": "yes"}
        )
        self.assertEqual(status, 403, body[:200])

    def test_f28_htaccess_setenv_and_setenvif_feed_authorization(self):
        status, _, body = request(self.port, "/env/secret.txt")
        self.assertEqual(status, 200, body[:200])
        status, _, body = request(self.port, "/env/secret.txt", {"X-Block": "yes"})
        self.assertEqual(status, 403, body[:200])
        status, _, body = request(self.port, "/env/allowed.txt")
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"WALLET-SETENV-ALLOWED", body)

    def test_f29_indexignore_hides_matching_entries(self):
        for path in ("/indexignore/", "/indexignore-main/"):
            status, _, body = request(self.port, path)
            self.assertEqual(status, 200, f"{path}: {body[:200]}")
            text = body.decode("utf-8", "replace")
            self.assertIn("public.txt", text)
            self.assertNotIn("wallet.secret", text)

    def test_f30_directory_without_slash_uses_trailing_slash_policy(self):
        status, _, body = request(self.port, "/admin")
        self.assertNotEqual(status, 200, body[:200])
        self.assertNotIn(b"WALLET-DIR-SECRET", body)
        status, _, body = request(self.port, "/admin/")
        self.assertEqual(status, 403, body[:200])

    def test_f31_capture_only_alias_cannot_re_root_outside_its_base(self):
        status, _, body = request(self.port, f"/escape{self.alias_secret}")
        self.assertEqual(status, 404, body[:200])
        self.assertNotIn(b"WALLET-ALIAS-SECRET", body)

    def test_f32_unsafe_prefix_stat_does_not_change_the_authorization_base(self):
        status, _, body = request(self.port, "/unsafe/rewrite-secret.txt")
        self.assertNotEqual(status, 200, body[:200])
        self.assertNotIn(b"WALLET-REWRITE-SECRET", body)

    def test_transform_rewrite_effects_are_rechecked_for_original_url(self):
        status, _, body = request(self.port, "/env-rewrite")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"hello", body)

    def test_transform_original_url_gate_uses_original_request_context(self):
        status, _, body = request(self.port, "/query-rewrite?orig=1")
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"hello", body)
        status, _, body = request(self.port, "/query-rewrite?orig=2")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"hello", body)

    def test_f35_proxy_host_validation(self):
        """F35: a request-derived forwarded host cannot reach the upstream head.

        A tab is legal in an HTTP header value but illegal in a host authority,
        so the request parser accepts it and only the proxy component check
        rejects it.  The upstream must not be contacted at all.
        """
        before = Backend.hits
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            sock.sendall(
                b"GET /front HTTP/1.1\r\n"
                b"Host: evil\texample.com\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            )
            response = b""
            while True:
                part = sock.recv(4096)
                if not part:
                    break
                response += part
        finally:
            sock.close()
        self.assertEqual(Backend.hits, before, "injected host reached the upstream")
        self.assertNotIn(b"WALLET-BACKEND-SECRET", response)
        self.assertNotIn(b"X-Injected", response)
        status = int(response.split(b" ", 2)[1]) if b" " in response else 0
        self.assertIn(status, (400, 502), response[:200])

    def test_f34_cache_is_partitioned_by_authorization_headers(self):
        headers = {"X-Tenant": "alpha"}
        status, response_headers, body = request(
            self.port, "/tenant/cacheme.cgi", headers
        )
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"WALLET-TENANT-CACHE", body)
        self.assertEqual(response_headers.get("X-Cache"), "MISS")
        status, response_headers, body = request(
            self.port, "/tenant/cacheme.cgi", headers
        )
        self.assertEqual(status, 200, body[:200])
        self.assertEqual(response_headers.get("X-Cache"), "HIT")
        status, _, body = request(
            self.port, "/tenant/cacheme.cgi", {"X-Tenant": "beta"}
        )
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"WALLET-TENANT-CACHE", body)

    def test_f36_htaccess_requestheader_fails_closed(self):
        status, _, body = request(self.port, "/reqheader/secret.txt")
        self.assertEqual(status, 500, body[:200])
        self.assertNotIn(b"WALLET-REQHEADER-SECRET", body)

    def test_f38_cgi_receives_remote_user_and_auth_type(self):
        status, _, body = request(self.port, "/cgiauth/who.cgi")
        self.assertEqual(status, 401, body[:200])
        token = base64.b64encode(b"alice:alicepw").decode()
        status, _, body = request(
            self.port,
            "/cgiauth/who.cgi",
            {"Authorization": f"Basic {token}"},
        )
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"REMOTE_USER=[alice]", body)
        self.assertIn(b"AUTH_TYPE=[Basic]", body)

    def test_f39_single_file_alias_reads_target_htaccess(self):
        status, _, body = request(self.port, "/wallet")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"WALLET-SINGLE-FILE-ALIAS-SECRET", body)

    def test_f39_single_file_alias_dispatches_cgi_target(self):
        for path in ("/run", "/exec"):
            status, _, body = request(self.port, path)
            self.assertEqual(status, 200, f"{path}: {body[:200]}")
            self.assertIn(b"WALLET-ALIAS-CGI-EXECUTED", body)
            self.assertNotIn(b"#!/bin/sh", body)

    def test_f40_limit_options_execcgi_is_enforced(self):
        status, _, body = request(self.port, "/limit-cgi/script.cgi")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"WALLET-LIMIT-EXECCGI-BYPASS", body)

    def test_f41_symlinked_cgi_and_fastcgi_use_actual_target_policy(self):
        for path in (
            "/private-cgi/admin.cgi",
            "/public-cgi/link.cgi",
            "/public-cgi/link.cgi/anything",
            "/private-cgi/secret.php",
            "/public-cgi/link.php",
        ):
            status, _, body = request(self.port, path)
            self.assertEqual(status, 403, f"{path}: {body[:200]}")
            self.assertNotIn(b"WALLET-PRIVATE-CGI-SECRET", body)
            self.assertNotIn(b"WALLET-PRIVATE-PHP-SECRET", body)

    def test_f45_expression_file_test_is_confined_to_docroot(self):
        status, _, body = request(self.port, "/exprtest/secret.txt")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"WALLET-EXPR-CONFINEMENT", body)

    def test_f42_capture_only_alias_cannot_read_serverroot(self):
        for rel in (".htpasswd", "rewrite-secret.txt", "vp.conf"):
            status, _, body = request(self.port, f"/escape{self.base}/{rel}")
            self.assertEqual(status, 404, f"{rel}: {body[:200]}")
            self.assertNotIn(b"WALLET-REWRITE-SECRET", body)
            self.assertNotIn(b"ServerRoot", body)
            self.assertNotIn(b"alice:", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
