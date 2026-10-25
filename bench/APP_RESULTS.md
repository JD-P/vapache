# PHP-FPM and Gunicorn application benchmark


Generated: 2026-10-25T00:42:17.869151+00:00


Method: 5 x 3s samples per server after warm-up; PHP-FPM over a Unix socket, Gunicorn with 8 sync workers behind the HTTP proxy; access logs disabled.


| scenario | apache req/s | vapache req/s | ratio | apache mean ms | vapache mean ms | apache p99 ms | vapache p99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| PHP-FPM /index.php | 42866 | 55373 | 1.29x | 0.87 | 0.87 | 4.82 | 7.65 |
| Gunicorn /app/hello | 22332 | 24624 | 1.10x | 6.45 | 1.42 | 12.60 | 5.58 |

## Reading the numbers

- Both handlers are deliberately trivial; this isolates the front-end/FastCGI/proxy hop rather than application work.
- PHP-FPM uses a Unix socket and is the production-shaped PHP path. Native `php-cgi` is not used here.
- Gunicorn uses eight default sync workers; vapache intentionally does not pool backend connections without strict response-framing checks. A real WSGI request with application latency will spend most of its time in the app, not this hop.
- Run-to-run variance is material on a shared host; the ratios are more useful than absolute req/s.
