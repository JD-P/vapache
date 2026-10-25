# Feature benchmark: vapached vs. Apache httpd

Generated: 2026-10-25T00:16:23.660562+00:00

Method: 1 x 1s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2 with four load-generator threads. HTTP/2 uses 64 clients x 16 streams; the 1 MB case uses 16 x 4 and CGI uses 16-32 clients.

| feature | apache req/s | vapache req/s | ratio | apache mean ms | vapache mean ms |
|---|---:|---:|---:|---:|---:|
| static index (small) | 52548 | 107963 | 2.05x | 1.63 | 0.92 |
| static 1.1KB | 68734 | 130230 | 1.89x | 1.14 | 0.43 |
| static 10KB | 74138 | 118774 | 1.60x | 1.11 | 0.46 |
| static 1MB | 9287 | 11078 | 1.19x | 1.95 | 0.86 |
| HEAD 1.1KB | 99664 | 105700 | 1.06x | 0.64 | 0.60 |
| 304 conditional | 124828 | 133763 | 1.07x | 0.45 | 0.42 |
| 206 range | 78759 | 129172 | 1.64x | 1.04 | 0.44 |
| empty file | 128147 | 146339 | 1.14x | 0.44 | 0.39 |
| directory index | 73083 | 98369 | 1.35x | 1.14 | 0.56 |
| autoindex | 68164 | 85806 | 1.26x | 0.88 | 0.66 |
| directory redirect | 159104 | 157963 | 0.99x | 0.36 | 0.35 |
| 301 redirect | 187685 | 208644 | 1.11x | 0.29 | 0.26 |
| alias | 52241 | 112440 | 2.15x | 1.56 | 0.55 |
| custom 404 | 76344 | 109528 | 1.43x | 1.12 | 0.52 |
| MIME AddType | 86596 | 145797 | 1.68x | 0.94 | 0.36 |
| access allow (IP) | 84263 | 140492 | 1.67x | 0.97 | 0.38 |
| access deny (IP) | 139581 | 215778 | 1.55x | 0.62 | 0.24 |
| <Limit> GET | 84068 | 138299 | 1.65x | 0.94 | 0.38 |
| <LimitExcept> GET | 83554 | 140110 | 1.68x | 0.94 | 0.39 |
| Satisfy Any | 85086 | 139351 | 1.64x | 0.96 | 0.38 |
| Satisfy All 403 | 139572 | 213487 | 1.53x | 0.67 | 0.26 |
| AllowMethods 405 | 137097 | 214236 | 1.56x | 0.69 | 0.23 |
| AuthMerging Or | 83917 | 135880 | 1.62x | 0.99 | 0.39 |
| AuthMerging And 403 | 135479 | 202046 | 1.49x | 0.70 | 0.25 |
| ElseIf header | 83054 | 134301 | 1.62x | 1.02 | 0.41 |
| DirectoryIndex CGI | 2781 | 8962 | 3.22x | 12.33 | 3.34 |
| ErrorDocument CGI | 2480 | 9466 | 3.82x | 13.93 | 3.16 |
| Basic auth 200 | 75744 | 116532 | 1.54x | 1.05 | 0.47 |
| Basic auth 401 | 156730 | 211082 | 1.35x | 0.35 | 0.24 |
| proxy static | 4241 | 3597 | 0.85x | 55.72 | 76.32 |
| <Proxy> deny | 153477 | 185541 | 1.21x | 0.53 | 0.36 |
| <ProxyMatch> allow | 3920 | 3237 | 0.83x | 15.65 | 42.89 |
| rewrite (server) | 81821 | 109827 | 1.34x | 1.05 | 0.51 |
| rewrite (.htaccess) | 62305 | 65215 | 1.05x | 1.44 | 0.97 |
| Header (.htaccess) | 72356 | 93884 | 1.30x | 1.16 | 0.61 |
| name-based vhost | 78949 | 110136 | 1.40x | 1.08 | 0.51 |
| CGI GET | 2227 | 5932 | 2.66x | 14.53 | 5.03 |
| CGI POST | 2093 | 5385 | 2.57x | 7.65 | 2.97 |
| HTTPS/1.1 static | 66688 | 86099 | 1.29x | 0.88 | 0.73 |
| HTTP/2 static | 45349 | 193744 | 4.27x | 22.49 | 5.00 |
| HTTP/2 10KB | 44308 | 146333 | 3.30x | 22.99 | 5.13 |
| HTTP/2 1MB | 4554 | 4889 | 1.07x | 11.37 | 10.03 |
| HTTP/2 range | 40146 | 196048 | 4.88x | 25.54 | 4.89 |
| HTTP/2 Basic auth | 38616 | 148640 | 3.85x | 26.47 | 6.73 |
| HTTP/2 vhost (SNI) | 39368 | 132576 | 3.37x | 26.00 | 7.62 |
| HTTP/2 CGI GET | 1258 | 6168 | 4.90x | 209.17 | 41.51 |
| HTTP/2 CGI POST | 1311 | 5680 | 4.33x | 49.01 | 11.25 |

## Startup checks

| metric | apache | vapache |
|---|---:|---:|
| config test (`-t`) median | 18.9 ms | 6.8 ms |
| processes after load | 7 | 33 |
| threads after load | 385 | 36 |
| PSS after load | 113.9 MiB | 58.0 MiB |

## Reading the numbers

- 3 scenario(s) were below Apache in this run; see the table (proxy/rewrite/CGI long-tail scenarios are the usual remaining cases).
- The feature-rich conformance configuration adds conditional rules, cache lookups, `.htaccess` candidates, vhost selection and proxy matching to every request; compare these ratios with the static `bench.py` results rather than treating them as a core-server regression.
- CGI now runs through a pool of small single-threaded worker processes. They are created only when the configuration can dispatch CGI; without CGI the server remains one process.
- The process count above includes the 16 CGI workers started for this CGI-capable config. PSS still includes their shared pages.
- HTTP/2 large-file throughput uses mmap-backed bodies and blocking-pool reads so one stream does not stall the other streams on a connection. Apache was run with stock mod_http2 settings and was not tuned.
- Not timed here: request-smuggling rejection, pipelining, HTTP/1.0, TLS 1.2/1.3, SNI certificate selection, graceful shutdown and log formatting. These are covered by `tests/conformance.py` (157 tests, all passing).
