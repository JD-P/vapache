# Pass 18 — adversarial break of HEAD `b8f68b5` ("Harden policy identity and proxy byte handling")

- **Date:** 2026-10-28
- **Subject:** `target/release/vapached` built at HEAD `b8f68b5`. No product source was edited. The retained additions for this pass are `adversarial/p18/exploit_p18.py`, this write-up and the `adversarial/README.md` index entry.
- **Oracle:** Apache/2.4.69 (Debian), `/usr/sbin/apache2 -X`, with `mod_proxy_fcgi` and `mod_cgi`; PHP-FPM 8.4.27 for the PHP cases. Loopback only.
- **Harness:** `adversarial/p18/exploit_p18.py` — **14 differential verdicts** across a PHP-FPM chain (A) and a CGI chain (B), with scoped-target, no-access-file, plain-`Require` and `AllowOverride AuthConfig` parity controls.
- **Retained evidence:** `/tmp/opencode/p18-harness` (fixtures, per-case Apache error logs, FPM access log and private FPM pool).
- **Method:** targeted audit of the `AllowOverrideList` admission predicate in `htaccess.rs`, followed by a live Apache-versus-vapache differential against a file-scoped upload-execution guard.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | vapache HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P18-A** | With `AllowOverride None` plus `AllowOverrideList Require`, an attacker-written `.htaccess` can contain a `<Files>` or `<FilesMatch>` section. Apache rejects the section itself (`500`, fail closed); vapache parses it unconditionally, permits the inner listed `Require`, and applies its file-scoped grant over the main `<FilesMatch ...> Require all denied` guard | `500`; `.htaccess: <Files not allowed here` (or `<FilesMatch not allowed here`) | `200`; uploaded PHP executes as the FPM worker (`PHPEXEC … uid=33`) or uploaded CGI executes as `www-data` (`EXEC uid=33`) | remote code execution / access-file section-gating bypass |

The exploit shape is a direct upload; it needs **no symlink**, no path traversal, and no FastCGI `SCRIPT_FILENAME` trick. An attacker who can write `.htaccess` into an upload directory, and can upload a PHP/CGI script there, adds:

```apache
<Files "shell.php">
    Require all granted
</Files>
```

The directory's main configuration is:

```apache
<Directory "/srv/app/www/uploads">
    AllowOverride None
    AllowOverrideList Require
    SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost"
    <FilesMatch "\.php$">
        Require all denied
    </FilesMatch>
</Directory>
```

Apache treats `AllowOverrideList Require` as permission for the **directive** `Require` only. A container section is not itself one of the listed directives, so Apache aborts the access file with `500` and never reaches the handler. Vapache's parser admits the container without consulting the list, then admits the inner `Require` because `Require` is in the list. The section's grant is scoped to `shell.php`, overrides the outer file-scoped deny, and the uploaded PHP/CGI is executed by the already-configured handler.

The scoped `ok.php`/`ok.cgi` control remains `403` on vapache, so the bypass is not a blanket directory grant. Apache returns `500` for both names because the attacker's access file itself is invalid under its configuration.

---

## 2. Observed differential

The harness uses sibling loopback instances of Apache and vapached with the same fixture. The main configuration for **A** uses a per-directory FastCGI handler (`P18-A`), a parent `<FilesMatch>` handler (`P18-A2b`), or the same outer deny with an access-file `<FilesMatch>` instead of `<Files>` (`P18-A2`). **B** uses `AddHandler cgi-script .cgi` plus `Options +ExecCGI`.

### 2.1 PHP-FPM: uploaded PHP becomes `www-data`

Fixture request target: `/uploads/shell.php?who=probe`. The uploaded file writes `PWNED who=probe uid=33` to `uploads/pwned.txt`, reads a file outside the web root (`S3CRET`), and echoes:

```
PHPEXEC who=probe uid=33 marker=S3CRET wrote=yes
```

Observed:

| Case | Apache 2.4.69 | vapache HEAD |
|---|---|---|
| `P18-A` `<Files "shell.php"> Require all granted`, per-directory FastCGI handler | `500`; `PWNED` absent | `200`; `PHPEXEC who=probe uid=33 marker=S3CRET wrote=yes`; `PWNED who=probe uid=33` written |
| `P18-A` same `.htaccess`, `/uploads/ok.php` (outside the `<Files>` grant) | `500`; `PWNED` absent | `403 Forbidden`; `PWNED` absent |
| `P18-A2` `<FilesMatch "^shell\.php$">` grant | `500`; `.htaccess: <FilesMatch not allowed here` | `200`; PHP executed, marker written |
| `P18-A2b` parent `<FilesMatch "\.php$"> SetHandler` plus the same section | `500`; `.htaccess: <Files not allowed here` | `200`; PHP executed, marker written |
| `P18-A3` no access file | `403`; outer deny | `403`; outer deny |
| `P18-A4` top-level `.htaccess` `Require all granted` | `403`; outer deny | `403`; outer deny |
| `P18-A5` `AllowOverride AuthConfig` plus the same `<Files>` section | `200`; `PHPEXEC … uid=33` | `200`; `PHPEXEC … uid=33` |
| `P18-A5` scoped `ok.php` under AuthConfig | `403` | `403` |

The **P18-A5** row is the parity control: when the override policy is `AuthConfig` rather than a directive-only `AllowOverrideList`, Apache accepts the section and both servers execute it. The differential is therefore the section gating specific to `AllowOverrideList`, not the section itself or the PHP handler.

The Apache error log for the exploit case contains:

```text
[core:alert] ... /tmp/opencode/p18-harness/P18-A-php-allowoverridelist/www/uploads/.htaccess: <Files not allowed here
```

The FPM access log records the backend execution on vapache:

```text
/tmp/opencode/p18-harness/P18-A-php-allowoverridelist/www/uploads/shell.php|/uploads/shell.php
```

There is no FPM line for the Apache request because Apache rejects the access file before reaching `mod_proxy_fcgi`.

### 2.2 CGI: arbitrary command execution

The same access-file section against a CGI handler (`AddHandler cgi-script .cgi`, `Options +ExecCGI`, outer `<FilesMatch "\.cgi$"> Require all denied`) produces:

| Case | Apache 2.4.69 | vapache HEAD |
|---|---|---|
| `P18-B` `<Files "shell.cgi"> Require all granted` | `500`; `PWNED` absent | `200`; `EXEC uid=33 who=probe`; `PWNED who=probe uid=33` written |
| `P18-B` `/uploads/ok.cgi` | `500`; `PWNED` absent | `403`; `PWNED` absent |
| `P18-B2` no access file | `403` | `403` |
| `P18-B3` plain top-level `Require all granted` | `403` | `403` |
| `P18-B4` `AllowOverride AuthConfig` plus the section | `200`; `EXEC uid=33` | `200`; `EXEC uid=33` |

The CGI script is a normal uploaded executable script (mode `0755`). Its output and the `pwned.txt` side effect show that vapache's handler path is not merely serving source: it runs the script as the worker user. Apache's `500` is a fail-closed response to the invalid `.htaccess`.

### 2.3 What the controls rule out

- **The outer guard is live without the access file.** `P18-A3`/`P18-B2`: both servers return `403` for the same uploaded script when no `.htaccess` is present.
- **A plain `Require` is not enough.** `P18-A4`/`P18-B3`: a top-level `.htaccess` `Require all granted` is accepted by Apache under the allow-list, but both servers still return `403`; the main `<FilesMatch>` deny is more specific. The attacker needs a file-scoped section.
- **The result is scoped.** The exact-name `<Files>` section grants `shell.php` only; `ok.php` remains `403` on vapache (Apache `500` for both because the access file is invalid).
- **The section is valid under ordinary category overrides.** `P18-A5`/`P18-B4`: `AllowOverride AuthConfig` with the same section returns `200` on both servers. The bug is not “vapache allows `<Files>` sections”; it is “vapache allows the section under `AllowOverrideList` where Apache does not.”
- **The FPM/CGI backend is otherwise functional.** A5/B4 parity demonstrates the handler and script; the exploit difference is the access-file admission, not a broken backend.

---

## 3. Root cause

### 3.1 The documented model

`docs/config-semantics.md:170-181` states:

```text
- `AllowOverrideList` permits individual directive names even when
  `AllowOverride None` would otherwise disable access files; the effective
  permission set is the union of both;
...
- the section containers `<If>`, `<IfFile>`, `<Files>`, `<FilesMatch>` do not
  themselves require a category; the directives **inside** them do;
```

The first sentence is correct for a **directive** admitted by the list. The second sentence is the incorrect generalization: Apache's `AllowOverrideList` does not admit a container section merely because a directive name inside it is listed. In Apache 2.4.69, a `.htaccess` containing `<Files>` or `<FilesMatch>` under `AllowOverrideList Require` is rejected as invalid:

```text
.htaccess: <Files not allowed here
```

Apache's category-based `AllowOverride AuthConfig`/`FileInfo` does allow these containers (our A5/B4 controls), so the model is right for categories and wrong for the directive-only list. The practical consequence is a fail-open policy: Apache returns `500`; vapache applies the file-scoped grant and continues.

### 3.2 The parser branch

`crates/server/src/htaccess.rs:1135-1176` handles the two container forms:

```rust
"files" | "filesmatch" => {
    // The override category applies to the directives inside
    // the section, not to the section itself.
    if require_only {
        return Err(format!("line {}: <{name}> is not allowed here", *i));
    }
    let pat = args.join(" ");
    let kind = ...;
    let mut inner = Scope::default();
    let mut inner_rules = Vec::new();
    parse_block(
        cfg,
        lines,
        i,
        &mut inner,
        &mut inner_rules,
        mode,
        allow_list,
        ...
    )?;
    rules.push(ScopeRule {
        kind,
        delta: inner,
        ...
    });
}
```

`mode` and `allow_list` are passed into the recursive parse, but the branch never checks them for the **container**. It only checks `require_only` (a different nested-section restriction). The comment states the exact invariant that Apache disproves for `AllowOverrideList`.

The inner `Require` is then admitted by `directive_allowed_list`:

```rust
// crates/server/src/htaccess.rs:1811-1822
fn directive_allowed_list(
    mode: OverrideMode,
    allow_list: &[String],
    name: &str,
    args: &[String],
) -> bool {
    if allow_list
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(name))
    {
        return true;
    }
    ...
}
```

With `AllowOverrideList Require`, the inner `Require` passes because its name is in the allow-list. The container never reaches an equivalent gate. The resulting `ScopeRule` is a file-phase rule (`MatchKind::Files`/`FilesMatch`), so it is applied to the request's basename after the main `<FilesMatch ...> Require all denied` of the uploads directory and the section-scoped grant wins for `shell.php`.

In short: the code and documentation model `AllowOverrideList` as a union of individually admitted directives, but Apache also gates the **section wrapper**. Vapache applies the wrapper and the inner listed directive, turning a fail-closed Apache configuration into a fail-open vapache one.

### 3.3 Why the file-scoped wrapper matters

The attacker cannot use a top-level `Require all granted` for this bypass: under the same allow-list, Apache and vapache both accept it, but the main `<FilesMatch>` deny is still more specific and both return `403` (A4/B3). The `<Files>`/`<FilesMatch>` section is the mechanism that targets the denied basename; vapache permits it, Apache rejects it. The unit of the bypass is therefore the **container**, not merely the `Require` directive.

---

## 4. Exploit chain

### 4.1 PHP-FPM deployment

A typical hardening posture for an upload directory is:

```apache
<Directory "/srv/app/www/uploads">
    AllowOverride None
    AllowOverrideList Require
    SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost"
    <FilesMatch "\.php$">
        Require all denied
    </FilesMatch>
</Directory>
```

The `AllowOverrideList Require` is intended to permit small, per-directory authorization adjustments without granting `FileInfo`, `Options` or arbitrary `.htaccess` content. The `<FilesMatch>` deny is the execution guard for uploaded PHP. The handler can instead be placed in a parent:

```apache
<Directory "/srv/app/www">
    <FilesMatch "\.php$">
        SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost"
    </FilesMatch>
</Directory>
```

Both forms were tested (A and A2b); both execute on vapache and return `500` on Apache after the access-file section is added.

Attacker steps:

1. Upload `shell.php` (arbitrary PHP) and `.htaccess` into `/srv/app/www/uploads/` through an application that allows file writes there.
2. Write the section:
   ```apache
   <Files "shell.php">
       Require all granted
   </Files>
   ```
3. Request `/uploads/shell.php`.

Observed on the harness:

```text
Apache:  500  <Files not allowed here (access file rejected)
vapache: 200  PHPEXEC who=probe uid=33 marker=S3CRET wrote=yes
              pwned.txt: PWNED who=probe uid=33
```

The PHP process is the FPM worker (`uid=33`); the payload reads a file outside the document root and writes a marker. Arbitrary PHP code can call `system`, open sockets, modify application files, or read secrets within the worker's permissions.

### 4.2 CGI deployment

The CGI form uses the same access-file section and a normal handler configuration:

```apache
<Directory "/srv/app/www/uploads">
    AllowOverride None
    AllowOverrideList Require
    Options +ExecCGI
    AddHandler cgi-script .cgi
    <FilesMatch "\.cgi$">
        Require all denied
    </FilesMatch>
</Directory>
```

With an uploaded `shell.cgi` and `.htaccess`:

```apache
<Files "shell.cgi">
    Require all granted
</Files>
```

Apache returns `500` (`<Files not allowed here`); vapache returns `200` and runs the script as `www-data`:

```text
EXEC uid=33 who=probe
pwned.txt: PWNED who=probe uid=33
```

`ok.cgi` remains `403` on vapache, so the grant is scoped to the attacker's filename.

---

## 5. Impact and preconditions

**Impact.** A remote attacker who can write `.htaccess` and a PHP/CGI script into an affected upload directory obtains **remote code execution as the web-worker user** on vapache. The harness demonstrates this with both a PHP-FPM backend and a POSIX CGI backend. The attacker can read files available to the worker (the harness reads a file outside the web root), write files in the upload tree, and run arbitrary commands through the executed script. Apache's response is a fail-closed `500`; the same access file does not execute there.

**Preconditions.**

1. **Write access to an access file and a script** in a directory served by vapache. This is the same upload/`.htaccess` primitive used by the other access-file findings; the application must permit the `.htaccess` name (directly or through a rename/upload path).
2. **A directive-only override policy**: `AllowOverride None` plus a nonempty `AllowOverrideList` containing `Require` (or an equivalent policy that admits the inner `Require` but not the section). The exact hardening posture in the fixture is `AllowOverrideList Require`. This is not the Apache default, but it is a valid least-privilege configuration.
3. **An execution handler for the uploaded script**: a per-directory or parent FastCGI `SetHandler`, or CGI `AddHandler` with `Options +ExecCGI`. The PHP handler can be the documented FastCGI spelling.
4. **A file-scoped authorization guard** on the upload path, e.g. `<FilesMatch "\.php$"> Require all denied` or `<Files "*.cgi"> Require all denied`, which the attacker's section can target. Without such a guard, the uploaded script may already execute on both servers and there is no differential to exploit.
5. **No broader `AllowOverride` that admits the section on Apache.** With the tested `AllowOverride AuthConfig` (A5/B4), Apache accepts the section and both servers execute; ordinary category modes such as `All` likewise admit the section. This finding is specific to the directive-only `AllowOverrideList`.

A `<Location>` guard outside the file-scoped section still binds in the negative probe (both servers deny); the exploit targets the file-scoped authorization gate in the fixture. The no-`.htaccess` controls show that gate is otherwise effective.

**Severity.** Remote code execution, configuration-gated. In a deployment that uses the listed posture, the upload guard is the only barrier between an upload primitive and code execution; the differential is a high-impact fail-open. It is not a default-configuration RCE: `AllowOverrideList` is an opt-in policy, and a deployment with `AllowOverride All` is not affected by this exact section-gating mismatch.

---

## 6. Relationship to P17 and other findings

P18 is separate from P17:

- **P17** is a FastCGI `SCRIPT_FILENAME` canonicalization bug. A symlink named `.txt` points at `.php`; Apache forwards the lexical `.txt` to PHP-FPM and FPM's `security.limit_extensions` refuses it, while vapache forwards the canonical `.php` and executes it. P17's differential is at the **backend script-identity** layer and requires a symlink; its Apache response is `403 Access denied.`
- **P18** has no symlink and no canonical/lexical backend identity. Apache rejects the attacker's `.htaccess` at **access-file parse time** (`500`, `<Files not allowed here`); vapache accepts the container section and applies a file-scoped authorization grant. The upload is requested directly and executes. The two findings should not be merged: fixing P17's `SCRIPT_FILENAME` does not affect P18, and fixing P18's section gating does not affect P17.

P18 also differs from the P14 `<Files>` phase-order and P12/P13 handler-classification findings: those involve conflicting config/access-file scopes or canonical-target classification; P18 is a section-container admission mismatch under `AllowOverrideList`, observed with both PHP-FPM and CGI and with a clean A5/B4 parity control.

---

## 7. Reproduction

```sh
cargo build --release -p vapached
python3 adversarial/p18/exploit_p18.py
# 14 verdict(s) passed
```

Optional evidence modes:

```sh
python3 adversarial/p18/exploit_p18.py A          # PHP-FPM chain
python3 adversarial/p18/exploit_p18.py B          # CGI chain (no PHP-FPM required)
python3 adversarial/p18/exploit_p18.py --show-fpm-log
```

The harness starts its own PHP-FPM pool under `/tmp/opencode/p18-harness/fpm` with
`php_admin_value[security.limit_extensions] = .php .phar`, and starts Apache and
vapached on sibling loopback ports with separate pid files. It retains:

- `/tmp/opencode/p18-harness/<case>/error.log` — Apache's `<Files not allowed here` / `<FilesMatch not allowed here` evidence;
- `/tmp/opencode/p18-harness/fpm/access.log` — the PHP-FPM request for the vapache execution;
- `/tmp/opencode/p18-harness/<case>/www/uploads/pwned.txt` — the code-execution marker path checked per request (removed after each check); the run output records the observed `PWNED who=probe uid=33` content;
- `/tmp/opencode/p18-final-run.txt` — the final 14-verdict harness output;
- rewritten `apache.conf`/`vapache.conf` fixtures for each case.

The final retained run produced **14 PASS** verdicts, including the two exploit paths and all controls. The Apache oracle runs `-X`; the harness binds loopback ports only and keeps its cleanup inside `/tmp/opencode/p18-harness`.

---

## 8. Suggested remediation direction

The product source was not changed for this pass. The required behavior is to match Apache's access-file admission:

- In an `AllowOverrideList` context, a container section must not be admitted solely because a directive inside it appears in the list. `<Files>`/`<FilesMatch>` (and the other containers named in `docs/config-semantics.md`) should be rejected or skipped unless the active `AllowOverride` mode permits the container, matching Apache's `500` fail-closed behavior in the tested configuration.
- Update the invariant at `docs/config-semantics.md:178-179`: container sections do not require a category under category-based `AllowOverride`, but `AllowOverrideList` is not a union that implicitly admits them.
- Add an Apache differential regression with `AllowOverride None` + `AllowOverrideList Require`, an outer `<FilesMatch>` deny, and an access file containing `<Files>`/`<FilesMatch>`; assert the access file is rejected (or otherwise not applied) rather than executing the target.
- Keep the existing A5/B4 `AllowOverride AuthConfig` controls: they ensure the fix does not reject sections where Apache accepts them.
