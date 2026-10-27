#!/usr/bin/env python3
"""Compare Apache/vapached acceptance of security-sensitive config contexts.

Many directives are accepted by one server in a context where the other
rejects them.  A permissive parser is not automatically a vulnerability, but
for access-control directives it is exactly the kind of surprise that turns
into a bypass.  This harness deliberately uses `-t` only: the question is
whether the configuration is accepted, not how it behaves after startup.
The STRICT_CASES rows additionally check that `vapached --strict-config`
fails where Apache `apache2 -t` fails (H8 promoted directive drops).
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VAPACHED = Path(os.environ.get("VAPACHED", ROOT / "target" / "release" / "vapached"))
APACHE = shutil.which("apache2") or "/usr/sbin/apache2"
MODDIR = Path("/usr/lib/apache2/modules")
BASE = Path(tempfile.mkdtemp(prefix="vapache-config-validity-"))
DOCROOT = BASE / "www"
PORT = 18190

MODULES = [
    "mpm_event_module",
    "mime_module",
    "dir_module",
    "alias_module",
    "autoindex_module",
    "authz_core_module",
    "authz_host_module",
    "access_compat_module",
    "allowmethods_module",
    "headers_module",
    "setenvif_module",
    "auth_basic_module",
    "authn_core_module",
    "authn_file_module",
    "authz_user_module",
    "authz_groupfile_module",
    "rewrite_module",
    "proxy_module",
    "expires_module",
]


def prefix(port: int) -> str:
    lines = []
    for mod in MODULES:
        lines.append(f"LoadModule {mod} {MODDIR}/mod_{mod.replace('_module','')}.so")
    lines += [
        f'ServerRoot "{BASE}"',
        f"Listen {port}",
        "User www-data",
        "Group www-data",
        f"PidFile {BASE}/logs/httpd-{port}.pid",
        f"ErrorLog {BASE}/logs/error-{port}.log",
        "LogLevel warn",
        "ServerName localhost",
        f'DocumentRoot "{DOCROOT}"',
        "TypesConfig /etc/mime.types",
        "DirectoryIndex index.html",
        "<Directory />",
        "    AllowOverride None",
        "    Require all denied",
        "</Directory>",
        f'<Directory "{DOCROOT}">',
        "    Options FollowSymLinks",
        "    AllowOverride None",
        "    Require all granted",
        "</Directory>",
    ]
    return "\n".join(lines) + "\n"


CASES = [
    ("server-level AllowOverride", "AllowOverride All\n"),
    (
        "AllowOverride in Location",
        f'<Location "/x">\n    AllowOverride All\n</Location>\n',
    ),
    (
        "AllowOverride in Directory tilde regex",
        f'<Directory ~ "^{DOCROOT}/x">\n    AllowOverride All\n</Directory>\n',
    ),
    (
        "AllowOverride in DirectoryMatch",
        f'<DirectoryMatch "^{DOCROOT}/x">\n    AllowOverride All\n</DirectoryMatch>\n',
    ),
    (
        "AllowOverride in Files",
        '<Files "x">\n    AllowOverride All\n</Files>\n',
    ),
    (
        "AllowOverride in VirtualHost",
        f"<VirtualHost *:{PORT}>\n    ServerName vh.test\n    AllowOverride All\n</VirtualHost>\n",
    ),
    (
        "nested Directory",
        f'<Directory "{DOCROOT}">\n    <Directory "{DOCROOT}/sub">\n        AllowOverride None\n    </Directory>\n</Directory>\n',
    ),
    (
        "Directory inside Location",
        f'<Location "/x">\n    <Directory "{DOCROOT}/x">\n        Require all granted\n    </Directory>\n</Location>\n',
    ),
    (
        "Location inside Directory",
        f'<Directory "{DOCROOT}/x">\n    <Location "/x">\n        Require all granted\n    </Location>\n</Directory>\n',
    ),
    (
        "Files inside Location",
        '<Location "/x">\n    <Files "x">\n        Require all denied\n    </Files>\n</Location>\n',
    ),
    (
        "Limit outside Directory",
        "<Limit POST>\n    Require all denied\n</Limit>\n",
    ),
    (
        "RequireAll at server level",
        "<RequireAll>\n    Require all granted\n</RequireAll>\n",
    ),
    (
        "RequireAll in VirtualHost",
        f"<VirtualHost *:{PORT}>\n    ServerName vh.test\n    <RequireAll>\n        Require all granted\n    </RequireAll>\n</VirtualHost>\n",
    ),
    (
        "Satisfy at server level",
        "Satisfy any\n",
    ),
    (
        "Order at server level",
        "Order allow,deny\n",
    ),
    (
        "Allow at server level",
        "Allow from all\n",
    ),
    (
        "AuthType at server level",
        "AuthType Basic\n",
    ),
    (
        "Require at server level",
        "Require all denied\n",
    ),
    (
        "Require in VirtualHost",
        f"<VirtualHost *:{PORT}>\n    ServerName vh.test\n    Require all denied\n</VirtualHost>\n",
    ),
    (
        "Limit in Location",
        '<Location "/x">\n    <Limit POST>\n        Require all denied\n    </Limit>\n</Location>\n',
    ),
    (
        "Limit in Files",
        '<Files "x">\n    <Limit POST>\n        Require all denied\n    </Limit>\n</Files>\n',
    ),
    (
        "RequireAll inside If at server level",
        "<If \"%{HTTP:X} == 'yes'\">\n    <RequireAll>\n        Require all granted\n    </RequireAll>\n</If>\n",
    ),
    (
        "AllowOverride in If inside Directory",
        f"<Directory \"{DOCROOT}\">\n    <If \"%{{HTTP:X}} == 'yes'\">\n        AllowOverride All\n    </If>\n</Directory>\n",
    ),
    (
        "Directory inside Proxy",
        '<Proxy "http://example.invalid/">\n    <Directory "/srv">\n        Require all granted\n    </Directory>\n</Proxy>\n',
    ),
    (
        "Proxy inside Directory",
        f'<Directory "{DOCROOT}">\n    <Proxy "http://example.invalid/">\n        Require all granted\n    </Proxy>\n</Directory>\n',
    ),
    (
        "Directory inside If",
        f'<If "%{{HTTP:X}} == \'yes\'">\n    <Directory "{DOCROOT}">\n        Require all granted\n    </Directory>\n</If>\n',
    ),
    (
        "Require inside If at server level",
        "<If \"%{HTTP:X} == 'yes'\">\n    Require all denied\n</If>\n",
    ),
    (
        "AuthType inside If at server level",
        "<If \"%{HTTP:X} == 'yes'\">\n    AuthType Basic\n</If>\n",
    ),
    (
        "AllowOverrideList at server level",
        "AllowOverrideList Require\n",
    ),
    (
        "AllowOverrideList None with directive",
        f'<Directory "{DOCROOT}">\n    AllowOverride None\n    AllowOverrideList None Require\n</Directory>\n',
    ),
    (
        "valid AllowOverrideList",
        f'<Directory "{DOCROOT}">\n    AllowOverride None\n    AllowOverrideList Require\n</Directory>\n',
    ),
    (
        "Include fragment",
        f"Include {BASE}/inc.conf\n",
    ),
    (
        "IncludeOptional missing",
        f"IncludeOptional {BASE}/does-not-exist.conf\n",
    ),
    (
        "valid Directory AllowOverride",
        f'<Directory "{DOCROOT}/ok">\n    AllowOverride All\n</Directory>\n',
    ),
]

# H8: promoted directive drops.  Apache rejects each of these snippets at
# plain `-t`; vapached in compatible mode keeps loading with a warning (a
# documented compatibility divergence), but `--strict-config` must refuse to
# run so the configuration cannot pass a strict deployment unnoticed.
STRICT_CASES = [
    ("AddType requires two args", "AddType image/png\n"),
    ("AddHandler requires two args", "AddHandler cgi-script\n"),
    ("Header requires an action pair", "Header set\n"),
    ("ExpiresByType requires type + code", "ExpiresByType text/html\n"),
    ("ProxyPass requires path and url", "ProxyPass /x\n"),
    ("RewriteOptions unknown token", "RewriteEngine On\nRewriteOptions Bogus\n"),
    (
        "Options unknown token",
        f'<Directory "{DOCROOT}">\n    Options Bogus\n</Directory>\n',
    ),
    (
        "ProxyPass failonstatus unparsable",
        "ProxyPass /b http://127.0.0.1:1/ failonstatus=9xx,foo\n",
    ),
    (
        "ProxySet failonstatus unparsable",
        '<Proxy "balancer://alpha">\n'
        '    BalancerMember "http://127.0.0.1:1"\n'
        "    ProxySet failonstatus=9xx,foo\n"
        "</Proxy>\n",
    ),
]


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=20)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if not VAPACHED.exists():
        sys.exit(f"missing {VAPACHED}; cargo build --release first")
    if not Path(APACHE).exists():
        sys.exit(f"missing Apache httpd at {APACHE}")
    try:
        DOCROOT.mkdir(parents=True, exist_ok=True)
        os.chmod(BASE, 0o755)
        os.chmod(DOCROOT, 0o755)
        (BASE / "logs").mkdir(exist_ok=True)
        os.chmod(BASE / "logs", 0o777)
        (BASE / "inc.conf").write_text(
            f'<Directory "{DOCROOT}/inc">\n    Require all denied\n</Directory>\n'
        )
        (DOCROOT / "inc").mkdir(exist_ok=True)
        failures = 0
        for name, snippet in CASES:
            acfg = BASE / "apache.conf"
            vcfg = BASE / "vapache.conf"
            acfg.write_text(prefix(PORT) + snippet)
            vcfg.write_text(prefix(PORT + 1) + snippet)
            a = run([APACHE, "-t", "-f", str(acfg)])
            v = run([str(VAPACHED), "-t", "-f", str(vcfg)])
            aok = a.returncode == 0
            vok = v.returncode == 0
            status = "ok  " if aok == vok else "DIFF"
            if aok != vok:
                failures += 1
            print(f"{status} {name}: apache={aok} vapache={vok}")
            if args.verbose or aok != vok:
                print(f"  apache: {(a.stderr or a.stdout).strip()[-500:]}")
                print(f"  vapache: {(v.stderr or v.stdout).strip()[-500:]}")
        strict_failures = 0
        for name, snippet in STRICT_CASES:
            acfg = BASE / "apache.conf"
            vcfg = BASE / "vapache.conf"
            acfg.write_text(prefix(PORT) + snippet)
            vcfg.write_text(prefix(PORT + 1) + snippet)
            a = run([APACHE, "-t", "-f", str(acfg)])
            v = run([str(VAPACHED), "-t", "-f", str(vcfg)])
            s = run([str(VAPACHED), "-t", "--strict-config", "-f", str(vcfg)])
            aok = a.returncode == 0
            vok = v.returncode == 0
            sok = s.returncode == 0
            # Expected triple: apache refuses the snippet, vapached warns but
            # loads in compatible mode, and strict mode refuses as well.
            bad = (not aok) and vok and sok
            status = "strict" if not bad else "STRICT-DIFF"
            if bad:
                strict_failures += 1
            print(f"{status} {name}: apache={aok} vapache={vok} strict={sok}")
            if args.verbose or bad:
                print(f"  apache: {(a.stderr or a.stdout).strip()[-400:]}")
                print(f"  vapache: {(v.stderr or v.stdout).strip()[-300:]}")
                print(f"  strict: {(s.stderr or s.stdout).strip()[-300:]}")
        print(f"\n{failures} context divergence(s)")
        print(f"{strict_failures} strict refusal divergence(s)")
        print(f"tree: {BASE}")
        return 1 if failures or strict_failures else 0
    finally:
        shutil.rmtree(BASE, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
