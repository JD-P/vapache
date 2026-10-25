# Coverage

Snapshot: 2026-10-23, after `<Limit>`/`<LimitExcept>`, `Satisfy`,
`AuthMerging`, `AllowMethods`, `<Proxy>` authorization and
`<ElseIf>`/`<Else>` support, fail-closed security directives, request-body
spooling, graceful-stop draining, reload cache isolation, and read-limit
enforcement.

```

Filename                      Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover
--------------------------------------------------------------------------------------------------------------------------------------------
server/src/access.rs                 1114                126    88.69%          50                7    86.00%       628             99    84.24%
server/src/auth.rs                    445                 40    91.01%          20                3    85.00%       241             20    91.70%
server/src/cache.rs                  1086                204    81.22%          68               11    83.82%       594            107    81.99%
server/src/cgi.rs                    1589                257    83.83%          95               30    68.42%       892            134    84.98%
server/src/compression.rs             750                 79    89.47%          39                1    97.44%       394             42    89.34%
server/src/config.rs                 7274               1636    77.51%         261               49    81.23%      4759           1050    77.94%
server/src/expires.rs                 257                 29    88.72%          20                0   100.00%       157             19    87.90%
server/src/expr.rs                   1546                480    68.95%          63               21    66.67%       822            209    74.57%
server/src/fastcgi.rs                 889                142    84.03%          40                8    80.00%       521             82    84.26%
server/src/files.rs                  1212                218    82.01%          40                5    87.50%       713            116    83.73%
server/src/h2.rs                      772                209    72.93%          45               22    51.11%       408             83    79.66%
server/src/htaccess.rs               2336                316    86.47%          70               11    84.29%      1351            204    84.90%
server/src/http.rs                   1202                319    73.46%          67                7    89.55%       794            224    71.79%
server/src/log.rs                     768                146    80.99%          39                8    79.49%       489             73    85.07%
server/src/main.rs                    936                323    65.49%          38                8    78.95%       574            246    57.14%
server/src/ocsp.rs                    703                161    77.10%          26                4    84.62%       382             77    79.84%
server/src/proxy.rs                  2680                295    88.99%         152               35    76.97%      1655            160    90.33%
server/src/rewrite.rs                2937                486    83.45%          93               19    79.57%      1533            235    84.67%
server/src/server.rs                 2378                423    82.21%          84               21    75.00%      1544            271    82.45%
server/src/status.rs                   44                  0   100.00%           3                0   100.00%        19              0   100.00%
server/src/tls.rs                     552                 89    83.88%          31               12    61.29%       294             42    85.71%
server/src/util.rs                    653                 89    86.37%          39                6    84.62%       322             39    87.89%
verified/src/lib.rs                  1187                 88    92.59%          27                0   100.00%       784             73    90.69%
--------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                               33310               6155    81.52%        1410              288    79.57%     19870           3605    81.86%
```

## Expression engine coverage

`expr.rs` is at **74.57% lines** and **66.67% functions**. The covered surface
includes:

- boolean/int/string comparisons and concatenation
- `&&`, `||`, `!`, `-n`, `-z`
- `-in` lists, regex literals and `$0..$N` captures
- request/header/environment variables and common `TIME_*`/`API_VERSION`
- `req()`, `http()`, `env()`, `toupper`, `tolower`, `escape`, `unescape`,
  `sha1`, `md5`, base64 functions
- `-f`, `-d`, `-e`, `-s`, `-F`, `-U`, `-R`, `-ipmatch`, `-strmatch`,
  `-strcmatch`, `-fnmatch`
- `Require expr`, `.htaccess <If>`, and config `<If>`/`<IfFile>`

Not covered / not implemented: `LogMessage` expression interpolation, some
rare string/list/function forms, and a few Apache 2.4.68+ file-function
restrictions.

## Still missing from the first-six list

- OCSP responder error-cache timeout policies (`SSLStaplingCache` is still
  treated as local persistence rather than a shared socache).
- Rewrite edge semantics: `dbm` maps and exact per-directory `[DPI]`
  path-info handling.
- Advanced balancer policies beyond route-cookie stickiness, `failonstatus`,
  passive failover and GET/HEAD health checks.
- `mod_cache_socache` and `mod_file_cache` (disk warm-start metadata is
  implemented).
- `mod_info` (basic `mod_status` is implemented).

`llvm-cov` reported 135 functions with mismatched data when merging the release
daemon with the debug unit-test objects; line coverage is unaffected, but
function percentages should be treated as approximate.

Reproduce with `tests/coverage.sh`. The report merges profiles from the real
`vapached` process driving the 157-test conformance suite with the Rust unit
test binaries (141 library tests plus 4 CLI/daemon tests).
