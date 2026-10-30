# Linux packages

The `vapache` packages install:

- `/usr/sbin/vapached` — the server;
- `/usr/sbin/vapachectl` — an Apache-layout-aware control wrapper;
- `/usr/sbin/vapache-switch` — an explicit, interactive service switch;
- `/usr/lib/systemd/system/vapache.service` — the systemd service unit; and
- documentation below `/usr/share/doc/vapache`.

They intentionally do not install, replace, or edit Apache configuration.
`vapachectl` uses `/etc/apache2/apache2.conf` on Debian-family systems or
`/etc/httpd/conf/httpd.conf` on RPM-family systems. Set both
`VAPACHE_CONFDIR` and `VAPACHE_CONFIG` to use another existing Apache layout.
Debian-family Apache layouts use symlinks such as `sites-enabled/*`, while
vapache deliberately refuses to follow symlinks for privileged configuration
inputs. The wrapper therefore materializes the selected Apache tree into a
root-controlled runtime snapshot below `/run/vapache`; it rejects writable,
non-root-owned, or out-of-tree source links when run as root. When that
configuration requests a default-off vapache capability, the wrapper uses
`vapached --audit-capabilities` to derive only the missing declarations and
writes them into the snapshot. The original Apache tree remains unchanged.
Set `VAPACHE_AUTO_CAPABILITIES=0` to require explicit declarations in the
source configuration. Snapshotting is automatically limited to Debian-style
enabled-config layouts; set `VAPACHE_SNAPSHOT_CONFIG=0` or `1` to override
that choice. On the stock `/etc/httpd` layout, the runtime overlay also
supplies RHEL's compiled-in `/run/httpd/httpd.pid` default, which is not
present as a directive in `httpd.conf`.

Installation does not enable or start vapache and does not stop Apache. Run
`sudo vapache-switch` when ready. The helper validates the configuration,
shows which Apache service it found, asks for confirmation, and only then
disables/stops Apache and enables/starts vapache. If vapache fails to start,
the helper restores Apache's previous active/enabled state.

The release binary targets `x86_64-unknown-linux-musl` and is a static PIE. It
therefore has no glibc version floor. Vapache still requires Linux 5.6 or newer
for its fail-closed `openat2` path-resolution boundary.

The workflow also uploads the loose `vapached` executable. GitHub's artifact
transport may clear its executable bit; run `chmod +x vapached-*` after a loose
download, or use the tar, Debian, or RPM payload, which preserves file modes.
