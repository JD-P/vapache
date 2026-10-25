//! Security-critical, mechanically verified primitives used by `vapached`.
//!
//! Every function in this crate is proved with Verus.  The runtime calls these
//! functions directly; there is no "verified model" that diverges from the
//! code that ships.  Proofs are erased at compile time, so the only cost is
//! the inherent cost of the algorithm itself.
//!
//! The properties proved here are deliberately stated as *security*
//! postconditions, not merely functional ones:
//!
//! * `percent_decode_path`: output is printable ASCII, contains no NUL, no
//!   backslash, and (when encoded separators are disabled, the Apache default)
//!   no slash can be introduced via percent-encoding.
//! * `normalize_uri_path`: output is an absolute path with no `.`/`..`
//!   segments, no duplicate slashes, and no traversal bytes.  Consequently
//!   joining it beneath a document root cannot escape that root in the string
//!   domain.  The server additionally enforces containment at the kernel
//!   level with `openat2(RESOLVE_BENEATH)`; the verified property is the
//!   policy half of a defence-in-depth design.
//! * `sanitize_header_value` / `valid_token`: emitted header values contain no
//!   CR, LF or NUL; header names and methods are RFC 9110 tokens.
//! * `parse_request_head` / `request_framing`: the method and every header name
//!   are tokens, header values contain no control bytes, request targets split
//!   into well-formed origin-form paths, and `Transfer-Encoding` can never
//!   coexist with `Content-Length`.  Chunked framing is HTTP/1.1 only.
//! * `parse_byte_range`: a satisfiable range always has `start <= end` and
//!   `end < file_len`; all arithmetic is checked.

use vstd::prelude::*;

verus! {

// ---------------------------------------------------------------------------
// Shared specs
// ---------------------------------------------------------------------------

/// Bytes that may appear in a decoded URI path: printable ASCII except `\`.
/// A space is permitted after percent-decoding (`%20`), matching Apache, and
/// cannot appear literally in a request target because the request-line
/// parser splits on spaces.  Control bytes, DEL and `\` remain rejected.
pub open spec fn is_path_byte(b: u8) -> bool {
    b >= 0x20 && b <= 0x7e && b != 0x5c
}

pub open spec fn all_path_bytes(s: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < s.len() ==> is_path_byte(s[i])
}

pub open spec fn no_crlf_nul(s: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < s.len() ==> s[i] != 0x0a && s[i] != 0x0d && s[i] != 0
}

spec fn hex_val(b: u8) -> Option<u8> {
    if b >= b'0' && b <= b'9' {
        Some((b - b'0') as u8)
    } else if b >= b'a' && b <= b'f' {
        Some((b - b'a' + 10) as u8)
    } else if b >= b'A' && b <= b'F' {
        Some((b - b'A' + 10) as u8)
    } else {
        None
    }
}

spec fn hex_pair(hi: u8, lo: u8) -> Option<u8> {
    match (hex_val(hi), hex_val(lo)) {
        (Some(h), Some(l)) => Some((h * 16 + l) as u8),
        _ => None,
    }
}

/// Executable mirror of the spec predicate, proved equivalent.
fn path_byte_ok(b: u8) -> (ok: bool)
    ensures ok == is_path_byte(b),
{
    b >= 0x20 && b <= 0x7e && b != 0x5c
}

fn hex_val_exec(b: u8) -> (v: Option<u8>)
    ensures v == hex_val(b),
{
    if b >= b'0' && b <= b'9' {
        Some((b - b'0') as u8)
    } else if b >= b'a' && b <= b'f' {
        Some((b - b'a' + 10) as u8)
    } else if b >= b'A' && b <= b'F' {
        Some((b - b'A' + 10) as u8)
    } else {
        None
    }
}

fn tchar_ok(b: u8) -> (ok: bool)
    ensures ok == is_tchar(b),
{
    (b >= b'a' && b <= b'z')
        || (b >= b'A' && b <= b'Z')
        || (b >= b'0' && b <= b'9')
        || b == b'!' || b == b'#' || b == b'$' || b == b'%' || b == b'&'
        || b == b'\'' || b == b'*' || b == b'+' || b == b'-' || b == b'.'
        || b == b'^' || b == b'_' || b == b'`' || b == b'|' || b == b'~'
}


// ---------------------------------------------------------------------------
// Percent decoding
// ---------------------------------------------------------------------------

/// Decode `%XX` escapes in a URI path.
///
/// Returns `None` for malformed escapes, encoded NUL/control bytes, encoded
/// backslashes, and (unless `allow_encoded_slash`) encoded slashes.  The
/// Apache default is `AllowEncodedSlashes Off`, which is also the safest
/// choice: decoding `%2F` before routing is the root cause of several httpd
/// path-confusion CVEs.
pub fn percent_decode_path(input: &[u8], allow_encoded_slash: bool) -> (out: Option<Vec<u8>>)
    ensures
        match out {
            Some(v) => {
                &&& all_path_bytes(v@)
                &&& v@.len() <= input@.len()
            }
            None => true,
        },
{
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i: usize = 0;
    while i < input.len()
        invariant
            0 <= i <= input.len(),
            out@.len() <= i,
            all_path_bytes(out@),
        decreases input.len() - i,
    {
        let b = input[i];
        if b == b'%' {
            if input.len() - i < 3 {
                return None;
            }
            assert(i + 2 < input.len());
            let hi = input[i + 1];
            let lo = input[i + 2];
            let decoded = match (hex_val_exec(hi), hex_val_exec(lo)) {
                (Some(h), Some(l)) => (h * 16 + l) as u8,
                _ => return None,
            };
            if !path_byte_ok(decoded) {
                return None;
            }
            if decoded == b'/' && !allow_encoded_slash {
                return None;
            }
            out.push(decoded);
            i = i + 3;
        } else {
            if !path_byte_ok(b) {
                return None;
            }
            out.push(b);
            i = i + 1;
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// URI path canonicalization
// ---------------------------------------------------------------------------

/// True when `i` is a segment boundary in `s`: the start of the path, the end
/// of the path, or a `/` separator.
pub open spec fn is_segment_boundary(s: Seq<u8>, i: int) -> bool {
    i == 0 || i == s.len() || (0 < i < s.len() && s[i] == b'/')
}

/// The canonical-path invariant enforced before any filesystem lookup.
///
/// A canonical path is absolute, contains only safe path bytes, has no empty,
/// `.` or `..` segments, no duplicate slashes, and no trailing slash (except
/// the root `/`).  These are exactly the properties that make a string-domain
/// join beneath a document root unable to escape that root.
pub open spec fn is_canonical_path(s: Seq<u8>) -> bool {
    &&& s.len() >= 1
    &&& s[0] == b'/'
    &&& all_path_bytes(s)
    &&& (s.len() == 1 || s[s.len() - 1] != b'/')
    &&& forall|i: int|
        0 <= i < s.len() - 1 ==> #[trigger] s[i] != b'/' || s[i + 1] != b'/'
    &&& forall|i: int|
        0 <= i < s.len() ==> #[trigger] s[i] != b'.' || !((i == 0 || s[i - 1] == b'/')
            && is_segment_boundary(s, i + 1))
    &&& forall|i: int|
        0 <= i < s.len() - 1 ==> #[trigger] s[i] != b'.' || s[i + 1] != b'.'
            || !((i == 0 || s[i - 1] == b'/')
            && is_segment_boundary(s, i + 2))
}

/// A non-empty path segment with only safe, non-separator bytes.  This is the
/// syntactic check; the parser separately decides whether the segment is a
/// no-op (`.`) or pops a prior segment (`..`).
pub open spec fn is_segment_bytes(input: Seq<u8>, start: int, end: int) -> bool {
    &&& 0 <= start < end <= input.len()
    &&& forall|i: int| start <= i < end ==> is_path_byte(input[i]) && input[i] != b'/'
}

/// A single non-empty path segment stored as a range in the input that is
/// safe to emit: it must not be `.` or `..`.
pub open spec fn is_segment_range(input: Seq<u8>, start: int, end: int) -> bool {
    &&& is_segment_bytes(input, start, end)
    &&& !(end - start == 1 && input[start] == b'.')
    &&& !(end - start == 2 && input[start] == b'.' && input[start + 1] == b'.')
}

pub open spec fn segment_ranges_ok(input: Seq<u8>, ranges: Seq<(usize, usize)>) -> bool {
    forall|k: int| 0 <= k < ranges.len() ==> #[trigger] is_segment_range(
        input,
        ranges[k].0 as int,
        ranges[k].1 as int,
    )
}

fn segment_bytes_ok(input: &[u8], start: usize, end: usize) -> (ok: bool)
    requires
        start <= end <= input.len(),
    ensures
        ok == is_segment_bytes(input@, start as int, end as int),
{
    if start == end {
        return false;
    }
    let mut i = start;
    while i < end
        invariant
            start <= i <= end <= input.len(),
            forall|k: int| start <= k < i ==> is_path_byte(input@[k]) && input@[k] != b'/',
        decreases end - i,
    {
        if !path_byte_ok(input[i]) || input[i] == b'/' {
            return false;
        }
        i = i + 1;
    }
    true
}

proof fn lemma_all_path_bytes_concat(a: Seq<u8>, b: Seq<u8>)
    requires
        all_path_bytes(a),
        all_path_bytes(b),
    ensures
        all_path_bytes(a + b),
{
    assert forall|i: int| 0 <= i < (a + b).len() implies is_path_byte((a + b)[i]) by {
        if i < a.len() {
            assert((a + b)[i] == a[i]);
        } else {
            assert((a + b)[i] == b[i - a.len()]);
        }
    }
}

proof fn lemma_append_segment(s: Seq<u8>, seg: Seq<u8>)
    requires
        is_canonical_path(s),
        seg.len() > 0,
        all_path_bytes(seg),
        forall|i: int| 0 <= i < seg.len() ==> seg[i] != b'/',
        !(seg.len() == 1 && seg[0] == b'.'),
        !(seg.len() == 2 && seg[0] == b'.' && seg[1] == b'.'),
    ensures
        is_canonical_path(if s.len() == 1 { s + seg } else { s + seq![b'/'] + seg }),
{
    let t = if s.len() == 1 { s + seg } else { s + seq![b'/'] + seg };
    assert(all_path_bytes(seq![b'/']));
    lemma_all_path_bytes_concat(s, if s.len() == 1 { seg } else { seq![b'/'] + seg });
    lemma_all_path_bytes_concat(seq![b'/'], seg);
    assert(all_path_bytes(t));
    assert(t.len() >= 1);
    assert(t[0] == b'/');
    assert(s.len() == 1 || s[s.len() - 1] != b'/');
    assert(t[t.len() - 1] == seg[seg.len() - 1]);
    assert(t[t.len() - 1] != b'/');
    assert forall|i: int| #![trigger t[i]] 0 <= i < t.len() - 1 implies !(t[i] == b'/' && t[i + 1] == b'/') by {
        if i < s.len() - 1 {
            assert(t[i] == s[i] && t[i + 1] == s[i + 1]);
        } else if i == s.len() - 1 {
            if s.len() > 1 {
                assert(t[i] == s[i] && t[i + 1] == b'/');
                assert(s[i] != b'/');
            }
        } else {
            let j = i - s.len();
            if s.len() == 1 {
                assert(t[i] == seg[j] && t[i + 1] == seg[j + 1]);
            } else {
                if j == 0 {
                    assert(t[i] == b'/');
                }
                if j == 1 {
                    assert(t[i] == seg[0] && seg[0] != b'/');
                }
                if j >= 2 {
                    assert(t[i] == seg[j - 1] && t[i + 1] == seg[j]);
                }
            }
        }
    }
    assert forall|i: int| #![trigger t[i]] 0 <= i < t.len() implies !(t[i] == b'.'
        && (i == 0 || t[i - 1] == b'/') && is_segment_boundary(t, i + 1)) by {
        if i < s.len() {
            // A dot that was not a complete segment inside `s` cannot become
            // one merely by appending bytes, except at the old end, where it
            // would already have been a complete `.` segment.
            if i == s.len() - 1 && s[i] == b'.' {
                assert(is_segment_boundary(s, i + 1));
                assert(!(i == 0 || s[i - 1] == b'/'));
            }
        } else if i == s.len() {
            if s.len() > 1 {
                assert(t[i] == b'/');
            } else {
                assert(t[i] == seg[0]);
                assert(i == 1);
                if i + 1 < t.len() {
                    assert(t[i + 1] == seg[1]);
                }
            }
        } else {
            let off: int = if s.len() == 1 { 0 } else { 1 };
            let j = i - off - s.len();
            assert(t[i] == seg[j]);
            if seg.len() == 1 {
                assert(is_segment_boundary(t, i + 1));
                assert(seg[0] != b'.');
            }
        }
    }
    assert forall|i: int| #![trigger t[i]] 0 <= i < t.len() - 1 implies !(t[i] == b'.' && t[i + 1] == b'.'
        && (i == 0 || t[i - 1] == b'/') && is_segment_boundary(t, i + 2)) by {
        if i + 1 < s.len() {
            // Both dots were already inside `s`, or the second one was the
            // last byte of `s`; in either case canonicality of `s` applies.
            if i + 2 == s.len() {
                assert(is_segment_boundary(s, i + 2));
            }
        } else if i == s.len() - 1 {
            if s.len() > 1 {
                assert(t[i] == s[i] && t[i + 1] == b'/');
                assert(s[i] != b'.' || s[i - 1] != b'/');
            }
        } else if i == s.len() {
            if s.len() > 1 {
                assert(t[i] == b'/');
            } else {
                assert(t[i] == seg[0]);
                assert(t[i + 1] == seg[1]);
                if seg.len() == 2 {
                    assert(is_segment_boundary(t, i + 2));
                }
            }
        } else {
            let off: int = if s.len() == 1 { 0 } else { 1 };
            let j = i - s.len() - off;
            assert(t[i] == seg[j] && t[i + 1] == seg[j + 1]);
            if j + 2 == seg.len() {
                assert(is_segment_boundary(t, i + 2));
            }
        }
    }
}

/// Canonicalize a decoded, absolute URI path.
///
/// Returns `None` when the path is relative, contains unsafe bytes, or climbs
/// above the root.  On success the result satisfies `is_canonical_path`:
/// absolute, no `.`/`..`/empty segments, no duplicate or trailing slashes, and
/// only printable ASCII except backslash.  The runtime uses this verified
/// function directly before any filesystem lookup.
pub fn normalize_uri_path(input: &[u8]) -> (out: Option<Vec<u8>>)
    ensures
        match out {
            Some(v) => is_canonical_path(v@),
            None => true,
        },
{
    if input.len() == 0 || input[0] != b'/' {
        return None;
    }
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut i: usize = 1;
    let mut start: usize = 1;
    while i <= input.len()
        invariant
            1 <= start <= i <= input.len(),
            segment_ranges_ok(input@, ranges@),
        decreases input.len() + 1 - i,
    {
        let at_end = i == input.len();
        if at_end || input[i] == b'/' {
            if start < i {
                if !segment_bytes_ok(input, start, i) {
                    return None;
                }
                if i - start == 1 && input[start] == b'.' {
                    // A single `.` segment is a no-op.
                } else if i - start == 2 && input[start] == b'.' && input[start + 1] == b'.' {
                    if ranges.pop().is_none() {
                        return None;
                    }
                } else {
                    ranges.push((start, i));
                    assert(is_segment_range(input@, start as int, i as int));
                    assert(segment_ranges_ok(input@, ranges@));
                }
            }
            if at_end {
                break;
            }
            start = i + 1;
        }
        i = i + 1;
    }
    assert(segment_ranges_ok(input@, ranges@));
    let mut out: Vec<u8> = Vec::new();
    out.push(b'/');
    let mut k: usize = 0;
    while k < ranges.len()
        invariant
            0 <= k <= ranges.len(),
            is_canonical_path(out@),
            segment_ranges_ok(input@, ranges@),
            k == 0 ==> out@.len() == 1,
            k > 0 ==> out@.len() > 1,
        decreases ranges.len() - k,
    {
        let (s, e) = ranges[k];
        assert(is_segment_range(input@, s as int, e as int));
        let ghost old_out = out@;
        let ghost seg = input@.subrange(s as int, e as int);
        if out.len() > 1 {
            out.push(b'/');
        }
        out.extend_from_slice(&input[s..e]);
        if k == 0 {
            assert(out@ == old_out + seg);
        } else {
            assert(out@ == old_out + seq![b'/'] + seg);
        }
        proof {
            lemma_append_segment(old_out, seg);
        }
        k = k + 1;
    }
    Some(out)
}

/// Encode a rewrite backreference or variable value for a URL substitution.
/// The adapter uses this by default so a capture containing `?` cannot turn
/// the remainder into a query-string injection.  `UnsafeAllow3F` is an
/// explicit opt-out at configuration time.
pub fn rewrite_backref_no_qmark(value: &[u8]) -> (out: Vec<u8>)
    ensures
        forall|i: int| 0 <= i < out@.len() ==> out@[i] != b'?',
{
    let mut out: Vec<u8> = Vec::with_capacity(value.len());
    let mut i: usize = 0;
    while i < value.len()
        invariant
            0 <= i <= value.len(),
            forall|j: int| 0 <= j < out@.len() ==> out@[j] != b'?',
        decreases value.len() - i,
    {
        if value[i] == b'?' {
            out.push(b'%');
            out.push(b'3');
            out.push(b'f');
        } else {
            out.push(value[i]);
        }
        i = i + 1;
    }
    out
}

/// ASCII-case-insensitive prefix predicate used for rewrite URL schemes.
pub open spec fn starts_with_ignore_ascii_case_spec(
    s: Seq<u8>,
    prefix: Seq<u8>,
) -> bool {
    s.len() >= prefix.len()
        && eq_ignore_ascii_case_spec(s.subrange(0, prefix.len() as int), prefix)
}

fn starts_with_ignore_ascii_case(s: &[u8], prefix: &[u8]) -> (ok: bool)
    ensures ok == starts_with_ignore_ascii_case_spec(s@, prefix@),
{
    if s.len() < prefix.len() {
        false
    } else {
        eq_ignore_ascii_case(&s[..prefix.len()], prefix)
    }
}

pub open spec fn ascii_digit(b: u8) -> bool {
    b >= b'0' && b <= b'9'
}

pub open spec fn all_ascii_digits(s: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < s.len() ==> ascii_digit(s[i])
}

pub open spec fn no_colon_from(s: Seq<u8>, start: int) -> bool {
    forall|j: int| start <= j && j < s.len() ==> s[j] != b':'
}

pub open spec fn digits_between(s: Seq<u8>, start: int, end: int) -> bool {
    forall|j: int| start <= j && j < end ==> ascii_digit(s[j])
}

/// Index of the last colon at or before `end`, or -1 when there is none.
pub open spec fn last_colon_from(s: Seq<u8>, end: int) -> int
    decreases end,
{
    if end <= 0 {
        -1
    } else if s[end - 1] == b':' {
        end - 1
    } else {
        last_colon_from(s, end - 1)
    }
}

/// Drop a trailing decimal port only when it follows the final colon.  A
/// bracketed IPv6 literal without a port has a non-digit suffix after its
/// last colon, so it is left unchanged.
pub open spec fn strip_port_spec(s: Seq<u8>) -> Seq<u8> {
    let colon = last_colon_from(s, s.len() as int);
    if colon >= 0 && colon + 1 < s.len()
        && digits_between(s, colon + 1, s.len() as int)
    {
        s.subrange(0, colon)
    } else {
        s
    }
}

proof fn lemma_last_colon_found(s: Seq<u8>, end: int, colon: int)
    requires
        0 <= colon < end,
        end <= s.len(),
        s[colon] == b':',
        forall|j: int| colon < j < end ==> s[j] != b':',
    ensures last_colon_from(s, end) == colon,
    decreases end,
{
    if end <= 0 {
    } else if s[end - 1] == b':' {
        assert(end - 1 == colon);
    } else {
        lemma_last_colon_found(s, end - 1, colon);
    }
}

proof fn lemma_last_colon_none(s: Seq<u8>, end: int)
    requires
        0 <= end <= s.len(),
        forall|j: int| 0 <= j < end ==> s[j] != b':',
    ensures last_colon_from(s, end) == -1,
    decreases end,
{
    if end <= 0 {
    } else {
        lemma_last_colon_none(s, end - 1);
    }
}

fn ascii_digit_exec(b: u8) -> (ok: bool)
    ensures ok == ascii_digit(b),
{
    b >= b'0' && b <= b'9'
}

fn copy_prefix(s: &[u8], n: usize) -> (out: Vec<u8>)
    requires n <= s.len(),
    ensures out@ == s@.subrange(0, n as int),
{
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut i: usize = 0;
    while i < n
        invariant
            i <= n,
            n <= s.len(),
            out@ == s@.subrange(0, i as int),
        decreases n - i,
    {
        out.push(s[i]);
        i = i + 1;
    }
    out
}

fn strip_port(s: &[u8]) -> (out: Vec<u8>)
    ensures out@ == strip_port_spec(s@),
{
    let mut i: usize = s.len();
    let mut found: Option<usize> = None;
    while i > 0
        invariant
            i <= s.len(),
            match found {
                Some(colon) => {
                    0 <= colon < s.len()
                        && s@[colon as int] == b':'
                        && no_colon_from(s@, colon as int + 1)
                }
                None => no_colon_from(s@, i as int),
            },
        decreases i,
    {
        i = i - 1;
        if s[i] == b':' && found.is_none() {
            found = Some(i);
        }
    }
    match found {
        Some(colon) => {
            assert(s@[colon as int] == b':');
            assert(no_colon_from(s@, colon as int + 1));
            proof { lemma_last_colon_found(s@, s.len() as int, colon as int); }
            if colon + 1 < s.len() {
                let mut j: usize = colon + 1;
                let mut all = true;
                while j < s.len()
                    invariant
                        colon + 1 <= j <= s.len(),
                        all == digits_between(s@, colon as int + 1, j as int),
                    decreases s.len() - j,
                {
                    if !ascii_digit_exec(s[j]) {
                        all = false;
                    }
                    j = j + 1;
                }
                if all {
                    assert(digits_between(s@, colon as int + 1, s.len() as int));
                    copy_prefix(s, colon)
                } else {
                    assert(!digits_between(s@, colon as int + 1, s.len() as int));
                    copy_prefix(s, s.len())
                }
            } else {
                assert(!(colon as int + 1 < s.len() as int));
                copy_prefix(s, s.len())
            }
        }
        None => {
            assert(no_colon_from(s@, 0));
            proof { lemma_last_colon_none(s@, s.len() as int); }
            copy_prefix(s, s.len())
        }
    }
}

/// Authority comparison for internalizing an absolute rewrite URL.  Exact
/// host:port equality is accepted, and the optional decimal port may be
/// dropped from both sides.  The compare is ASCII-case-insensitive, matching
/// the existing rewrite behavior.
pub fn rewrite_authority_equal(authority: &[u8], host: &[u8]) -> (equal: bool)
    ensures
        equal == (eq_ignore_ascii_case_spec(authority@, host@)
            || eq_ignore_ascii_case_spec(
                strip_port_spec(authority@),
                strip_port_spec(host@),
            )),
{
    let authority_host = strip_port(authority);
    let request_host = strip_port(host);
    eq_ignore_ascii_case(authority, host) || eq_ignore_ascii_case(&authority_host, &request_host)
}

/// The external-URL decision used by rewrite target resolution.  A target is
/// external if it is scheme-relative (`//...`) or an HTTP(S) URL, matching
/// Apache's case-insensitive scheme handling.
pub open spec fn rewrite_target_external_spec(target: Seq<u8>) -> bool {
    (target.len() >= 2 && target[0] == b'/' && target[1] == b'/')
        || (target.len() >= 7
            && lower_byte(target[0]) == b'h'
            && lower_byte(target[1]) == b't'
            && lower_byte(target[2]) == b't'
            && lower_byte(target[3]) == b'p'
            && target[4] == b':'
            && target[5] == b'/'
            && target[6] == b'/')
        || (target.len() >= 8
            && lower_byte(target[0]) == b'h'
            && lower_byte(target[1]) == b't'
            && lower_byte(target[2]) == b't'
            && lower_byte(target[3]) == b'p'
            && lower_byte(target[4]) == b's'
            && target[5] == b':'
            && target[6] == b'/'
            && target[7] == b'/')
}

pub fn rewrite_target_external(target: &[u8]) -> (external: bool)
    ensures external == rewrite_target_external_spec(target@),
{
    (target.len() >= 2 && target[0] == b'/' && target[1] == b'/')
        || (target.len() >= 7
            && lower_byte_exec(target[0]) == b'h'
            && lower_byte_exec(target[1]) == b't'
            && lower_byte_exec(target[2]) == b't'
            && lower_byte_exec(target[3]) == b'p'
            && target[4] == b':'
            && target[5] == b'/'
            && target[6] == b'/')
        || (target.len() >= 8
            && lower_byte_exec(target[0]) == b'h'
            && lower_byte_exec(target[1]) == b't'
            && lower_byte_exec(target[2]) == b't'
            && lower_byte_exec(target[3]) == b'p'
            && lower_byte_exec(target[4]) == b's'
            && target[5] == b':'
            && target[6] == b'/'
            && target[7] == b'/')
}

/// Add the single leading slash required for an internal rewrite target.
/// External targets are classified before this function is called.
pub fn rewrite_internal_path(joined: &[u8]) -> (out: Vec<u8>)
    ensures
        out@.len() == joined@.len() + (if joined@.len() > 0 && joined@[0] == b'/' { 0int } else { 1int }),
        out@.len() > 0,
        out@[0] == b'/',
{
    let mut out: Vec<u8> = Vec::with_capacity(joined.len());
    out.push(b'/');
    let start: usize = if joined.len() > 0 && joined[0] == b'/' { 1 } else { 0 };
    let mut i: usize = start;
    while i < joined.len()
        invariant
            start <= i <= joined.len(),
            out@.len() == 1 + (i - start),
            out@[0] == b'/',
        decreases joined.len() - i,
    {
        out.push(joined[i]);
        i = i + 1;
    }
    out
}

/// Admit an absolute filesystem target produced by a rewrite.  A file may
/// be served only below the request's document root, or below the server
/// root when the rule explicitly opted into `UnsafePrefixStat`.  This is the
/// CVE-2024-38475 boundary: a backreference or query value cannot turn an
/// absolute substitute into an arbitrary file read.
pub fn rewrite_filesystem_admit(
    is_file: bool,
    under_docroot: bool,
    under_server_root: bool,
    unsafe_prefix_stat: bool,
) -> (ok: bool)
    ensures
        ok == (is_file && (under_docroot || (unsafe_prefix_stat && under_server_root))),
{
    is_file && (under_docroot || (unsafe_prefix_stat && under_server_root))
}

/// Escape access-log text so a hostile request field cannot inject a
/// newline, NUL, terminal escape or quote/backslash sequence.  This is the
/// verified primitive used by the access-log formatter (CVE-2001-1556).
fn hex_digit(n: u8) -> (c: u8)
    requires n < 16,
    ensures c == (if n < 10 { b'0' + n } else { b'a' + (n - 10) }),
{
    if n < 10 {
        b'0' + n
    } else {
        b'a' + (n - 10)
    }
}

pub fn escape_log_bytes(input: &[u8]) -> (out: Vec<u8>)
    ensures no_crlf_nul(out@),
{
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i: usize = 0;
    while i < input.len()
        invariant
            0 <= i <= input.len(),
            no_crlf_nul(out@),
        decreases input.len() - i,
    {
        let b = input[i];
        if b == b'"' || b == b'\\' {
            out.push(b'\\');
            out.push(b);
        } else if b < 0x20 || b == 0x7f {
            let hi = hex_digit(b / 16);
            let lo = hex_digit(b % 16);
            out.push(b'\\');
            out.push(b'x');
            out.push(hi);
            out.push(lo);
        } else {
            out.push(b);
        }
        i = i + 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Header sanitization
// ---------------------------------------------------------------------------

/// Validate a header value before it is written to the wire.
///
/// Rejects CR, LF and NUL.  This is the single choke point for every header
/// the daemon emits, including headers derived from file names and CGI
/// output, which is how response-splitting vulnerabilities usually enter.
pub fn sanitize_header_value(input: &[u8]) -> (out: Option<Vec<u8>>)
    ensures
        match out {
            Some(v) => {
                &&& no_crlf_nul(v@)
                &&& v@.len() == input@.len()
                &&& forall|i: int| 0 <= i < v@.len() ==> v@[i] == input@[i]
            }
            None => true,
        },
{
    let mut i: usize = 0;
    while i < input.len()
        invariant
            i <= input.len(),
            forall|k: int| 0 <= k < i ==> #[trigger] input@[k] != 0
                && input@[k] != b'\r' && input@[k] != b'\n',
        decreases input.len() - i,
    {
        let b = input[i];
        if b == 0 || b == b'\r' || b == b'\n' {
            return None;
        }
        i = i + 1;
    }
    assert(no_crlf_nul(input@));
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut j: usize = 0;
    while j < input.len()
        invariant
            j <= input.len(),
            out@.len() == j,
            forall|k: int| 0 <= k < j ==> out@[k] == input@[k],
            no_crlf_nul(out@),
            no_crlf_nul(input@),
        decreases input.len() - j,
    {
        out.push(input[j]);
        j = j + 1;
    }
    Some(out)
}

/// HTTP token characters (RFC 9110 `tchar`).  Header names and methods are
/// tokens; using an allow-list prevents request smuggling via exotic
/// whitespace and control characters.
pub open spec fn is_tchar(b: u8) -> bool {
    ||| (b >= b'a' && b <= b'z')
    ||| (b >= b'A' && b <= b'Z')
    ||| (b >= b'0' && b <= b'9')
    ||| b == b'!' || b == b'#' || b == b'$' || b == b'%' || b == b'&'
    ||| b == b'\'' || b == b'*' || b == b'+' || b == b'-' || b == b'.'
    ||| b == b'^' || b == b'_' || b == b'`' || b == b'|' || b == b'~'
}

pub open spec fn all_tchars(s: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < s.len() ==> is_tchar(s[i])
}

proof fn lemma_all_tchars_index(s: Seq<u8>, i: int)
    requires all_tchars(s), 0 <= i < s.len(),
    ensures is_tchar(s[i]),
{
}

pub fn valid_token(input: &[u8]) -> (ok: bool)
    ensures ok == (input@.len() > 0 && all_tchars(input@)),
{
    if input.len() == 0 {
        return false;
    }
    let mut i: usize = 0;
    while i < input.len()
        invariant
            i <= input.len(),
            forall|j: int| 0 <= j < i ==> #[trigger] is_tchar(input@[j]),
        decreases input.len() - i,
    {
        if !tchar_ok(input[i]) {
            return false;
        }
        i = i + 1;
    }
    assert(all_tchars(input@));
    true
}

// ---------------------------------------------------------------------------
// Byte ranges
// ---------------------------------------------------------------------------

pub enum RangeDecision {
    /// The header is malformed or unsupported; RFC 9110 says ignore it.
    Ignore,
    /// Syntactically valid but no bytes overlap the representation.
    Unsatisfiable,
    /// Inclusive byte range fully inside the representation.
    Satisfiable { start: u64, end: u64 },
}

spec fn parse_digits(s: Seq<u8>, i: int, end: int) -> Option<u64>
    decreases end - i,
{
    if i >= end {
        Some(0)
    } else if s[i] < b'0' || s[i] > b'9' {
        None
    } else {
        let rest = parse_digits(s, i + 1, end);
        match rest {
            Some(v) => {
                if v > (u64::MAX - (s[i] - b'0') as u64) / 10 {
                    None
                } else {
                    Some((v + (s[i] - b'0') as u64 * 10) as u64)
                }
            }
            None => None,
        }
    }
}

/// Parse a single `bytes=` range against a representation of `len` bytes.
///
/// Supports `bytes=a-b`, `bytes=a-`, and `bytes=-n` (suffix).  Multi-range
/// requests are deliberately downgraded to `Ignore` (full response): Apache's
/// multi-range implementation was the subject of the Range DoS
/// (CVE-2011-3192), and browsers do not need it.
pub fn parse_byte_range(header: &[u8], len: u64) -> (d: RangeDecision)
    ensures
        match d {
            RangeDecision::Satisfiable { start, end } => start <= end && end < len,
            _ => true,
        },
{
    if header.len() < 6 {
        return RangeDecision::Ignore;
    }
    assert(header.len() >= 6);
    let mut i: usize = 0;
    // "bytes=" is case-insensitive.
    let prefix = b"bytes=";
    while i < 6
        invariant
            i <= 6,
            header.len() >= 6,
        decreases 6 - i,
    {
        assert(i < header.len());
        let a = header[i];
        let b = prefix[i];
        let al = if a >= b'A' && a <= b'Z' { (a + 32) as u8 } else { a };
        if al != b {
            return RangeDecision::Ignore;
        }
        i = i + 1;
    }
    // Reject multiple ranges / extra lists.
    let mut j: usize = 6;
    while j < header.len()
        invariant 6 <= j <= header.len(),
        decreases header.len() - j,
    {
        if header[j] == b',' {
            return RangeDecision::Ignore;
        }
        j = j + 1;
    }
    if header.len() == 6 {
        return RangeDecision::Ignore;
    }
    let mut k: usize = 6;
    let mut digits: u64 = 0;
    let mut have_start: bool = false;
    let mut overflow: bool = false;
    while k < header.len() && header[k] != b'-' && header[k] != b' '
        invariant 6 <= k <= header.len(),
        decreases header.len() - k,
    {
        let c = header[k];
        if c < b'0' || c > b'9' {
            return RangeDecision::Ignore;
        }
        let d = (c - b'0') as u64;
        if digits > (u64::MAX - d) / 10 {
            overflow = true;
        } else if !overflow {
            digits = digits * 10 + d;
        }
        have_start = true;
        k = k + 1;
    }
    if k >= header.len() || header[k] != b'-' {
        return RangeDecision::Ignore;
    }
    k = k + 1;
    let mut suffix: bool = false;
    if !have_start {
        suffix = true;
    }
    let mut end_digits: u64 = 0;
    let mut have_end: bool = false;
    let mut end_overflow: bool = false;
    while k < header.len()
        invariant k <= header.len(),
        decreases header.len() - k,
    {
        let c = header[k];
        if c < b'0' || c > b'9' {
            return RangeDecision::Ignore;
        }
        let d = (c - b'0') as u64;
        if end_digits > (u64::MAX - d) / 10 {
            end_overflow = true;
        } else if !end_overflow {
            end_digits = end_digits * 10 + d;
        }
        have_end = true;
        k = k + 1;
    }

    if len == 0 {
        return RangeDecision::Unsatisfiable;
    }
    if suffix {
        if !have_end || end_digits == 0 {
            return RangeDecision::Unsatisfiable;
        }
        let n = if end_overflow { len } else { end_digits };
        if n >= len {
            return RangeDecision::Satisfiable { start: 0, end: len - 1 };
        }
        return RangeDecision::Satisfiable { start: len - n, end: len - 1 };
    }
    if !have_start {
        return RangeDecision::Ignore;
    }
    if overflow || digits >= len {
        return RangeDecision::Unsatisfiable;
    }
    let s = digits;
    if !have_end {
        return RangeDecision::Satisfiable { start: s, end: len - 1 };
    }
    let e = if end_overflow || end_digits >= len { len - 1 } else { end_digits };
    if s > e {
        return RangeDecision::Unsatisfiable;
    }
    RangeDecision::Satisfiable { start: s, end: e }
}

// ---------------------------------------------------------------------------
// HTTP/1.1 request head parsing and framing
// ---------------------------------------------------------------------------

/// HTTP versions accepted on the wire.  HTTP/2 is framed by the `h2` crate,
/// so this parser only ever produces the two HTTP/1.x versions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HttpVersion {
    Http10,
    Http11,
}

/// Why a request head was rejected.  The server maps these variants to the
/// same status codes and messages it used before the parser moved here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HeadError {
    NulByte,
    TooManyEmptyLines,
    UnterminatedRequestLine,
    RequestLineTooLong,
    MissingMethod,
    MissingTarget,
    MissingVersion,
    WhitespaceInRequestLine,
    InvalidMethod,
    InvalidTargetByte,
    InvalidVersion,
    VersionNotSupported,
    UnterminatedHeaders,
    UnterminatedHeader,
    HeaderLineTooLong,
    ObsoleteFolding,
    MissingColon,
    InvalidHeaderName,
    InvalidHeaderValue,
    TooManyHeaders,
    DuplicateHost,
    MissingHost,
    InvalidHost,
    InvalidAuthority,
    NotOriginForm,
    FragmentInTarget,
    BothTransferEncodingAndContentLength,
    TransferEncodingInHttp10,
    UnsupportedTransferCoding,
    InvalidContentLength,
    ConflictingContentLength,
}

/// How the body of a request is delimited.  `Chunked` is only produced for
/// HTTP/1.1 and only when there is no `Content-Length` header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BodyFraming {
    None,
    Length(u64),
    Chunked,
}

/// The result of parsing one complete request head.  Header names are
/// lowercased; values are trimmed of leading/trailing OWS.
#[derive(Debug)]
pub struct ParsedHead {
    pub method: Vec<u8>,
    pub target: Vec<u8>,
    pub raw_path: Vec<u8>,
    pub query: Vec<u8>,
    pub version: HttpVersion,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub framing: BodyFraming,
    pub keep_alive: bool,
    pub expect_continue: bool,
}

pub open spec fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

pub open spec fn lower_byte(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' { ((b as int) + 32) as u8 } else { b }
}

pub open spec fn eq_ignore_ascii_case_spec(a: Seq<u8>, b: Seq<u8>) -> bool {
    a.len() == b.len()
        && forall|i: int| 0 <= i < a.len() ==> lower_byte(a[i]) == lower_byte(b[i])
}

pub open spec fn all_target_bytes(s: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < s.len() ==> s[i] >= 0x21 && s[i] != 0x7f
}

pub open spec fn valid_method(s: Seq<u8>) -> bool {
    s.len() > 0 && s.len() <= 64 && all_tchars(s)
}

pub open spec fn valid_target(s: Seq<u8>) -> bool {
    s.len() > 0 && all_target_bytes(s)
}

pub open spec fn valid_header_name(s: Seq<u8>) -> bool {
    s.len() > 0 && all_tchars(s)
}

/// Header values may contain HTAB and any byte above SP, except DEL.  Bytes
/// below SP other than HTAB (including CR, LF and NUL) are rejected.
pub open spec fn valid_header_value(s: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < s.len() ==> is_ows(s[i]) || (s[i] >= 0x20 && s[i] != 0x7f)
}

pub open spec fn trimmed_header_value(s: Seq<u8>) -> bool {
    s.len() == 0 || (!is_ows(s[0]) && !is_ows(s[s.len() - 1]))
}

pub open spec fn header_ok(h: (Vec<u8>, Vec<u8>)) -> bool {
    &&& valid_header_name(h.0@)
    &&& valid_header_value(h.1@)
    &&& trimmed_header_value(h.1@)
}

pub open spec fn headers_ok(hs: Seq<(Vec<u8>, Vec<u8>)>) -> bool {
    forall|i: int| 0 <= i < hs.len() ==> #[trigger] header_ok(hs[i])
}

pub open spec fn no_byte(s: Seq<u8>, b: u8) -> bool {
    forall|i: int| 0 <= i < s.len() ==> s[i] != b
}

pub open spec fn is_asterisk_path(s: Seq<u8>) -> bool {
    s.len() == 1 && s[0] == b'*'
}

pub open spec fn split_target_ok(target: Seq<u8>, path: Seq<u8>, query: Seq<u8>) -> bool {
    &&& path.len() > 0
    &&& (is_asterisk_path(path) || (path[0] == b'/' && no_byte(path, b'?')
        && no_byte(path, b'#')))
    &&& no_byte(query, b'#')
}

pub open spec fn name_transfer_encoding() -> Seq<u8> {
    b"transfer-encoding"@
}

pub open spec fn name_content_length() -> Seq<u8> {
    b"content-length"@
}

pub open spec fn has_header_range(
    hs: Seq<(Vec<u8>, Vec<u8>)>,
    lo: int,
    hi: int,
    name: Seq<u8>,
) -> bool {
    exists|i: int| lo <= i < hi && #[trigger] hs[i].0@ == name
}

pub open spec fn has_header(hs: Seq<(Vec<u8>, Vec<u8>)>, name: Seq<u8>) -> bool {
    has_header_range(hs, 0, hs.len() as int, name)
}

proof fn lemma_has_header_range_snoc(
    hs: Seq<(Vec<u8>, Vec<u8>)>,
    lo: int,
    hi: int,
    name: Seq<u8>,
)
    requires 0 <= lo <= hi < hs.len(),
    ensures
        has_header_range(hs, lo, hi + 1, name) == (has_header_range(hs, lo, hi, name)
            || hs[hi].0@ == name),
{
    assert(has_header_range(hs, lo, hi + 1, name) ==> (has_header_range(hs, lo, hi, name)
        || hs[hi].0@ == name)) by {
        if has_header_range(hs, lo, hi + 1, name) {
            let i = choose|i: int| lo <= i < hi + 1 && hs[i].0@ == name;
            if i < hi {
                assert(has_header_range(hs, lo, hi, name));
            } else {
                assert(i == hi);
                assert(hs[hi].0@ == name);
            }
        }
    }
    assert((has_header_range(hs, lo, hi, name) || hs[hi].0@ == name)
        ==> has_header_range(hs, lo, hi + 1, name)) by {
        if has_header_range(hs, lo, hi, name) {
            let i = choose|i: int| lo <= i < hi && hs[i].0@ == name;
            assert(lo <= i < hi + 1);
        } else {
            assert(lo <= hi < hi + 1);
        }
    }
}

pub open spec fn parsed_head_ok(h: ParsedHead) -> bool {
    &&& valid_method(h.method@)
    &&& valid_target(h.target@)
    &&& headers_ok(h.headers@)
    &&& split_target_ok(h.target@, h.raw_path@, h.query@)
    &&& !(has_header(h.headers@, name_transfer_encoding())
        && has_header(h.headers@, name_content_length()))
    &&& (h.framing == BodyFraming::Chunked ==> h.version == HttpVersion::Http11)
}

fn is_ows_exec(b: u8) -> (r: bool)
    ensures r == is_ows(b),
{
    b == b' ' || b == b'\t'
}

fn lower_byte_exec(b: u8) -> (l: u8)
    ensures l == lower_byte(b),
{
    if b >= b'A' && b <= b'Z' { (b + 32) as u8 } else { b }
}

proof fn lemma_lower_tchar(b: u8)
    requires is_tchar(b),
    ensures is_tchar(lower_byte(b)),
{
    if b >= b'A' && b <= b'Z' {
        assert(lower_byte(b) == b + 32);
        assert(lower_byte(b) >= b'a' && lower_byte(b) <= b'z');
    } else {
        assert(lower_byte(b) == b);
    }
}

fn trim_range(input: &[u8]) -> (r: (usize, usize))
    ensures
        0 <= r.0 <= r.1 <= input.len(),
        r.0 == input.len() || !is_ows(input@[r.0 as int]),
        r.1 == r.0 || !is_ows(input@[r.1 as int - 1]),
        forall|i: int| 0 <= i < r.0 ==> is_ows(input@[i]),
        forall|i: int| r.1 <= i < input.len() ==> is_ows(input@[i]),
{
    let mut start: usize = 0;
    while start < input.len() && is_ows_exec(input[start])
        invariant
            start <= input.len(),
            forall|i: int| 0 <= i < start ==> is_ows(input@[i]),
        decreases input.len() - start,
    {
        start = start + 1;
    }
    let mut end: usize = input.len();
    while end > start && is_ows_exec(input[end - 1])
        invariant
            start <= end <= input.len(),
            forall|i: int| end <= i < input.len() ==> is_ows(input@[i]),
        decreases end - start,
    {
        end = end - 1;
    }
    (start, end)
}

fn copy_range(input: &[u8], start: usize, end: usize) -> (out: Vec<u8>)
    requires start <= end <= input.len(),
    ensures out@ == input@.subrange(start as int, end as int),
{
    let mut out: Vec<u8> = Vec::with_capacity(end - start);
    out.extend_from_slice(&input[start..end]);
    out
}

fn copy_slice(input: &[u8]) -> (out: Vec<u8>)
    ensures out@ == input@,
{
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    out.extend_from_slice(input);
    out
}

/// Copy a header value while trimming surrounding optional whitespace.
fn trim_ows_copy(input: &[u8]) -> (out: Vec<u8>)
    requires valid_header_value(input@),
    ensures
        valid_header_value(out@),
        trimmed_header_value(out@),
        out@.len() <= input@.len(),
{
    let (start, end) = trim_range(input);
    let out = copy_range(input, start, end);
    proof {
        assert forall|i: int| 0 <= i < out@.len() implies is_ows(out@[i])
            || (out@[i] >= 0x20 && out@[i] != 0x7f) by {
            assert(out@[i] == input@[start as int + i]);
        }
        if out@.len() > 0 {
            assert(start < end);
            assert(!is_ows(input@[start as int]));
            assert(out@[0] == input@[start as int]);
            assert(!is_ows(out@[0]));
            assert(!is_ows(input@[end as int - 1]));
            assert(out@[out@.len() - 1] == input@[end as int - 1]);
            assert(!is_ows(out@[out@.len() - 1]));
        }
        assert(trimmed_header_value(out@));
    }
    out
}

fn find_crlf(input: &[u8], start: usize) -> (out: Option<usize>)
    requires start <= input.len(),
    ensures
        match out {
            Some(i) => {
                &&& start <= i
                &&& i + 1 < input.len()
                &&& input@[i as int] == b'\r'
                &&& input@[i as int + 1] == b'\n'
            }
            None => true,
        },
{
    let mut i: usize = start;
    while i < input.len()
        invariant start <= i <= input.len(),
        decreases input.len() - i,
    {
        if input[i] == b'\r' && i < input.len() - 1 && input[i + 1] == b'\n' {
            assert(i + 1 < input.len());
            return Some(i);
        }
        i = i + 1;
    }
    None
}

fn bytes_eq(a: &[u8], b: &[u8]) -> (ok: bool)
    ensures ok == (a@ == b@),
{
    if a.len() != b.len() {
        return false;
    }
    let mut i: usize = 0;
    while i < a.len()
        invariant
            i <= a.len(),
            a.len() == b.len(),
            forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases a.len() - i,
    {
        if a[i] != b[i] {
            return false;
        }
        i = i + 1;
    }
    assert(a@ =~= b@);
    true
}

fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> (ok: bool)
    ensures ok == eq_ignore_ascii_case_spec(a@, b@),
{
    if a.len() != b.len() {
        return false;
    }
    let mut i: usize = 0;
    while i < a.len()
        invariant
            i <= a.len(),
            a.len() == b.len(),
            forall|j: int| 0 <= j < i ==> lower_byte(a@[j]) == lower_byte(b@[j]),
        decreases a.len() - i,
    {
        if lower_byte_exec(a[i]) != lower_byte_exec(b[i]) {
            return false;
        }
        i = i + 1;
    }
    assert(eq_ignore_ascii_case_spec(a@, b@));
    true
}

fn lower_ascii(input: &[u8]) -> (out: Vec<u8>)
    requires all_tchars(input@),
    ensures
        out@.len() == input@.len(),
        all_tchars(out@),
        forall|i: int| 0 <= i < out@.len() ==> out@[i] == lower_byte(input@[i]),
{
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i: usize = 0;
    while i < input.len()
        invariant
            i <= input.len(),
            out@.len() == i,
            all_tchars(out@),
            all_tchars(input@),
            forall|j: int| 0 <= j < i ==> out@[j] == lower_byte(input@[j]),
        decreases input.len() - i,
    {
        proof {
            assert(i < input.len());
            lemma_all_tchars_index(input@, i as int);
            lemma_lower_tchar(input@[i as int]);
        }
        let l = lower_byte_exec(input[i]);
        out.push(l);
        i = i + 1;
    }
    out
}

fn parse_decimal_u64(input: &[u8]) -> (out: Option<u64>)
    ensures
        match out {
            Some(_) => input@.len() > 0
                && forall|i: int| 0 <= i < input@.len() ==> b'0' <= input@[i] && input@[i] <= b'9',
            None => true,
        },
{
    if input.len() == 0 {
        return None;
    }
    let mut v: u64 = 0;
    let mut i: usize = 0;
    while i < input.len()
        invariant
            i <= input.len(),
            forall|j: int| 0 <= j < i ==> b'0' <= input@[j] && input@[j] <= b'9',
        decreases input.len() - i,
    {
        let b = input[i];
        if b < b'0' || b > b'9' {
            return None;
        }
        let d = (b - b'0') as u64;
        if v > (u64::MAX - d) / 10 {
            return None;
        }
        assert(v <= (u64::MAX - d) / 10);
        assert(v * 10 <= u64::MAX - d);
        v = v * 10 + d;
        i = i + 1;
    }
    Some(v)
}

pub open spec fn no_byte_range(s: Seq<u8>, b: u8, lo: int, hi: int) -> bool {
    forall|i: int| lo <= i < hi ==> s[i] != b
}

proof fn lemma_no_byte_range_to_seq(s: Seq<u8>, b: u8, lo: int, hi: int)
    requires
        no_byte_range(s, b, lo, hi),
        0 <= lo <= hi <= s.len(),
    ensures no_byte(s.subrange(lo, hi), b),
{
    assert forall|i: int| 0 <= i < hi - lo implies s.subrange(lo, hi)[i] != b by {
        assert(s.subrange(lo, hi)[i] == s[lo + i]);
    }
}

proof fn lemma_split_root_ok()
    ensures split_target_ok(seq![b'/'], seq![b'/'], Seq::<u8>::empty()),
{
    assert(seq![b'/'].len() == 1);
    assert(!is_asterisk_path(seq![b'/']));
    assert(no_byte(seq![b'/'], b'?'));
    assert(no_byte(seq![b'/'], b'#'));
}

fn split_target(target: &[u8]) -> (res: Result<(Vec<u8>, Vec<u8>), HeadError>)
    requires valid_target(target@),
    ensures
        match res {
            Ok(pair) => split_target_ok(target@, pair.0@, pair.1@),
            Err(_) => true,
        },
{
    if target.len() == 1 && target[0] == b'*' {
        assert(target@ == seq![b'*']);
        assert(split_target_ok(target@, seq![b'*'], seq![]));
        return Ok((copy_slice(target), Vec::new()));
    }
    let mut start: usize = 0;
    if target.len() >= 7 && bytes_eq(&target[..7], b"http://") {
        start = 7;
    } else if target.len() >= 8 && bytes_eq(&target[..8], b"https://") {
        start = 8;
    }
    if start > 0 {
        let mut slash: usize = start;
        while slash < target.len() && target[slash] != b'/'
            invariant start <= slash <= target.len(),
            decreases target.len() - slash,
        {
            slash = slash + 1;
        }
        if slash == start {
            return Err(HeadError::InvalidAuthority);
        }
        let mut ai: usize = start;
        while ai < slash
            invariant start <= ai <= slash <= target.len(),
            decreases slash - ai,
        {
            if target[ai] == b'@' {
                return Err(HeadError::InvalidAuthority);
            }
            ai = ai + 1;
        }
        start = slash;
        if start == target.len() {
            let mut path: Vec<u8> = Vec::new();
            path.push(b'/');
            let query: Vec<u8> = Vec::new();
            proof {
                assert(path@ == seq![b'/']);
                assert(query@ == Seq::<u8>::empty());
                lemma_split_root_ok();
                assert(split_target_ok(target@, path@, query@));
            }
            return Ok((path, query));
        }
    }
    if target[start] != b'/' {
        return Err(HeadError::NotOriginForm);
    }
    let mut hash_i: usize = start;
    while hash_i < target.len()
        invariant
            start <= hash_i <= target.len(),
            no_byte_range(target@, b'#', start as int, hash_i as int),
        decreases target.len() - hash_i,
    {
        if target[hash_i] == b'#' {
            return Err(HeadError::FragmentInTarget);
        }
        hash_i = hash_i + 1;
    }
    assert(no_byte_range(target@, b'#', start as int, target.len() as int));

    let mut qpos: usize = start;
    while qpos < target.len() && target[qpos] != b'?'
        invariant
            start <= qpos <= target.len(),
            no_byte_range(target@, b'?', start as int, qpos as int),
        decreases target.len() - qpos,
    {
        qpos = qpos + 1;
    }
    assert(target@[start as int] == b'/');
    assert(qpos > start);
    let path = copy_range(target, start, qpos);
    let query = if qpos < target.len() {
        copy_range(target, qpos + 1, target.len())
    } else {
        Vec::new()
    };
    proof {
        assert(no_byte_range(target@, b'#', start as int, qpos as int));
        assert(no_byte_range(target@, b'?', start as int, qpos as int));
        lemma_no_byte_range_to_seq(target@, b'#', start as int, qpos as int);
        lemma_no_byte_range_to_seq(target@, b'?', start as int, qpos as int);
        assert(path@ == target@.subrange(start as int, qpos as int));
        assert(path@.len() > 0);
        assert(path@[0] == b'/');
        assert(no_byte(path@, b'?'));
        assert(no_byte(path@, b'#'));
        if qpos < target.len() {
            assert(no_byte_range(target@, b'#', (qpos + 1) as int, target.len() as int));
            lemma_no_byte_range_to_seq(target@, b'#', (qpos + 1) as int, target.len() as int);
            assert(query@ == target@.subrange((qpos + 1) as int, target.len() as int));
            assert(no_byte(query@, b'#'));
        } else {
            assert(query@.len() == 0);
        }
        assert(split_target_ok(target@, path@, query@));
    }
    Ok((path, query))
}

fn apply_connection_tokens(value: &[u8], keep_alive: bool) -> (out: bool) {
    let mut out = keep_alive;
    let mut i: usize = 0;
    while i <= value.len()
        invariant i <= value.len(),
        decreases value.len() + 1 - i,
    {
        let mut e: usize = i;
        while e < value.len() && value[e] != b','
            invariant i <= e <= value.len(),
            decreases value.len() - e,
        {
            e = e + 1;
        }
        let sub = &value[i..e];
        let (ts, te) = trim_range(sub);
        let tok = &sub[ts..te];
        if te > ts {
            if eq_ignore_ascii_case(tok, b"close") {
                out = false;
            } else if eq_ignore_ascii_case(tok, b"keep-alive") {
                out = true;
            }
        }
        if e == value.len() {
            break;
        }
        i = e + 1;
    }
    out
}

/// Determine how a request body is framed, rejecting every ambiguous
/// `Transfer-Encoding`/`Content-Length` combination.  This is the kernel that
/// prevents HTTP request smuggling.  Header names must already be lowercase;
/// `parse_request_head` is the only caller and canonicalizes them first.
fn request_framing(
    version: HttpVersion,
    headers: &[(Vec<u8>, Vec<u8>)],
) -> (res: Result<BodyFraming, HeadError>)
    ensures
        match res {
            Ok(f) => {
                &&& !(has_header(headers@, name_transfer_encoding())
                    && has_header(headers@, name_content_length()))
                &&& (f == BodyFraming::Chunked ==> version == HttpVersion::Http11)
                &&& (has_header(headers@, name_transfer_encoding())
                    ==> f == BodyFraming::Chunked)
            }
            Err(_) => true,
        },
{
    let mut te_seen: bool = false;
    let mut i: usize = 0;
    while i < headers.len()
        invariant
            i <= headers.len(),
            te_seen == has_header_range(headers@, 0, i as int, name_transfer_encoding()),
        decreases headers.len() - i,
    {
        let te_here = bytes_eq(&headers[i].0, b"transfer-encoding");
        proof {
            lemma_has_header_range_snoc(headers@, 0, i as int, name_transfer_encoding());
        }
        if te_here {
            assert(headers@[i as int].0@ == b"transfer-encoding"@);
            assert(headers@[i as int].0@ == name_transfer_encoding());
            te_seen = true;
        } else {
            assert(headers@[i as int].0@ != b"transfer-encoding"@);
            assert(headers@[i as int].0@ != name_transfer_encoding());
        }
        i = i + 1;
    }
    assert(has_header(headers@, name_transfer_encoding()) == te_seen);

    let mut cl_seen: bool = false;
    let mut j: usize = 0;
    while j < headers.len()
        invariant
            j <= headers.len(),
            cl_seen == has_header_range(headers@, 0, j as int, name_content_length()),
        decreases headers.len() - j,
    {
        let cl_here = bytes_eq(&headers[j].0, b"content-length");
        proof {
            lemma_has_header_range_snoc(headers@, 0, j as int, name_content_length());
        }
        if cl_here {
            assert(headers@[j as int].0@ == b"content-length"@);
            assert(headers@[j as int].0@ == name_content_length());
            cl_seen = true;
        } else {
            assert(headers@[j as int].0@ != b"content-length"@);
            assert(headers@[j as int].0@ != name_content_length());
        }
        j = j + 1;
    }
    assert(has_header(headers@, name_content_length()) == cl_seen);

    if te_seen {
        if cl_seen {
            return Err(HeadError::BothTransferEncodingAndContentLength);
        }
        match version {
            HttpVersion::Http10 => return Err(HeadError::TransferEncodingInHttp10),
            HttpVersion::Http11 => {}
        }
        assert(version == HttpVersion::Http11);
        let mut coding_count: usize = 0;
        let mut only_chunked: bool = true;
        let mut hi: usize = 0;
        while hi < headers.len()
            invariant hi <= headers.len(),
            decreases headers.len() - hi,
        {
            if bytes_eq(&headers[hi].0, b"transfer-encoding") {
                let value = &headers[hi].1;
                let mut vi: usize = 0;
                while vi <= value.len()
                    invariant vi <= value.len(),
                    decreases value.len() + 1 - vi,
                {
                    let mut ve: usize = vi;
                    while ve < value.len() && value[ve] != b','
                        invariant vi <= ve <= value.len(),
                        decreases value.len() - ve,
                    {
                        ve = ve + 1;
                    }
                    let sub = &value[vi..ve];
                    let (ts, te) = trim_range(sub);
                    let tok = &sub[ts..te];
                    if te > ts {
                        if coding_count == 0 {
                            coding_count = 1;
                        } else {
                            coding_count = 2;
                        }
                        if !eq_ignore_ascii_case(tok, b"chunked") {
                            only_chunked = false;
                        }
                    }
                    if ve == value.len() {
                        break;
                    }
                    vi = ve + 1;
                }
            }
            hi = hi + 1;
        }
        if coding_count != 1 || !only_chunked {
            return Err(HeadError::UnsupportedTransferCoding);
        }
        assert(te_seen);
        assert(has_header(headers@, name_transfer_encoding()));
        assert(!cl_seen);
        assert(!has_header(headers@, name_content_length()));
        return Ok(BodyFraming::Chunked);
    }
    if !cl_seen {
        assert(!has_header(headers@, name_transfer_encoding()));
        return Ok(BodyFraming::None);
    }
    let mut value: Option<u64> = None;
    let mut ci: usize = 0;
    while ci < headers.len()
        invariant ci <= headers.len(),
        decreases headers.len() - ci,
    {
        if bytes_eq(&headers[ci].0, b"content-length") {
            let (ts, te) = trim_range(&headers[ci].1);
            let n = match parse_decimal_u64(&headers[ci].1[ts..te]) {
                Some(n) => n,
                None => return Err(HeadError::InvalidContentLength),
            };
            match value {
                None => value = Some(n),
                Some(prev) => {
                    if prev != n {
                        return Err(HeadError::ConflictingContentLength);
                    }
                }
            }
        }
        ci = ci + 1;
    }
    assert(!has_header(headers@, name_transfer_encoding()));
    match value {
        Some(n) => {
            if n == 0 {
                Ok(BodyFraming::None)
            } else {
                Ok(BodyFraming::Length(n))
            }
        }
        None => Err(HeadError::InvalidContentLength),
    }
}

/// Parse and validate a complete HTTP/1.x request head (request line plus
/// header fields, including the terminating empty line).
///
/// The postcondition is the security contract: the method is a bounded token,
/// every header name is a token, every header value is free of CTLs/CR/LF/NUL
/// and surrounding OWS, the request target and split path are well formed, and
/// a `Transfer-Encoding` header can never coexist with `Content-Length`.
pub fn parse_request_head(
    head: &[u8],
    max_request_line: usize,
    max_fields: usize,
    max_field_size: usize,
) -> (res: Result<ParsedHead, HeadError>)
    ensures
        match res {
            Ok(h) => {
                &&& parsed_head_ok(h)
                &&& h.target@.len() <= max_request_line as int
                &&& h.headers@.len() <= max_fields as int
            }
            Err(_) => true,
        },
{
    let mut z: usize = 0;
    while z < head.len()
        invariant z <= head.len(),
        decreases head.len() - z,
    {
        if head[z] == 0 {
            return Err(HeadError::NulByte);
        }
        z = z + 1;
    }

    let mut pos: usize = 0;
    while pos < head.len() && pos < head.len() - 1
        && head[pos] == b'\r' && head[pos + 1] == b'\n'
        invariant pos <= head.len(),
        decreases head.len() - pos,
    {
        pos = pos + 2;
        if pos > 64 {
            return Err(HeadError::TooManyEmptyLines);
        }
    }

    let line_end = match find_crlf(head, pos) {
        Some(i) => i,
        None => return Err(HeadError::UnterminatedRequestLine),
    };
    if line_end - pos > max_request_line {
        return Err(HeadError::RequestLineTooLong);
    }
    let line = &head[pos..line_end];

    let mut sp1: Option<usize> = None;
    let mut sp2: Option<usize> = None;
    let mut extra_space: bool = false;
    let mut si: usize = 0;
    while si < line.len()
        invariant
            si <= line.len(),
            sp1.is_none() ==> sp2.is_none(),
            match sp1 {
                Some(a) => a < si,
                None => true,
            },
            match sp2 {
                Some(b) => b < si,
                None => true,
            },
            match sp1 {
                Some(a) => a < line.len(),
                None => true,
            },
            match sp2 {
                Some(b) => b < line.len(),
                None => true,
            },
            match (sp1, sp2) {
                (Some(a), Some(b)) => a < b,
                _ => true,
            },
        decreases line.len() - si,
    {
        if line[si] == b' ' {
            if sp1.is_none() {
                sp1 = Some(si);
            } else if sp2.is_none() {
                sp2 = Some(si);
                match sp1 {
                    Some(_a) => assert(_a < si),
                    None => {}
                }
            } else {
                extra_space = true;
            }
        }
        si = si + 1;
    }

    let method_start: usize = 0;
    let method_end: usize;
    let target_start: usize;
    let target_end: usize;
    let version_start: usize;
    match sp1 {
        None => {
            if line.len() == 0 {
                return Err(HeadError::MissingMethod);
            }
            return Err(HeadError::MissingTarget);
        }
        Some(a) => {
            if a == 0 {
                return Err(HeadError::MissingMethod);
            }
            assert(a < line.len());
            method_end = a;
            target_start = a + 1;
            match sp2 {
                None => {
                    if target_start >= line.len() {
                        return Err(HeadError::MissingTarget);
                    }
                    return Err(HeadError::MissingVersion);
                }
                Some(b) => {
                    assert(b < line.len());
                    assert(a < b);
                    if b == target_start {
                        return Err(HeadError::MissingTarget);
                    }
                    target_end = b;
                    version_start = b + 1;
                }
            }
        }
    }
    if extra_space {
        return Err(HeadError::WhitespaceInRequestLine);
    }

    let method = &line[method_start..method_end];
    let target = &line[target_start..target_end];
    let version_b = &line[version_start..];
    if !valid_token(method) || method.len() > 64 {
        return Err(HeadError::InvalidMethod);
    }
    if target.len() > max_request_line {
        return Err(HeadError::RequestLineTooLong);
    }
    let mut ti: usize = 0;
    while ti < target.len()
        invariant
            ti <= target.len(),
            forall|j: int| 0 <= j < ti ==> target@[j] >= 0x21 && target@[j] != 0x7f,
        decreases target.len() - ti,
    {
        let b = target[ti];
        if b < 0x21 || b == 0x7f {
            return Err(HeadError::InvalidTargetByte);
        }
        ti = ti + 1;
    }
    assert(valid_target(target@));
    let version = if bytes_eq(version_b, b"HTTP/1.1") {
        HttpVersion::Http11
    } else if bytes_eq(version_b, b"HTTP/1.0") {
        HttpVersion::Http10
    } else if version_b.len() >= 5 && bytes_eq(&version_b[..5], b"HTTP/") {
        return Err(HeadError::VersionNotSupported);
    } else {
        return Err(HeadError::InvalidVersion);
    };
    let method_v = copy_range(line, method_start, method_end);
    let target_v = copy_range(line, target_start, target_end);

    let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut count: usize = 0;
    let mut cur: usize = line_end + 2;
    loop
        invariant
            cur <= head.len(),
            count as int == headers@.len(),
            headers_ok(headers@),
            count <= max_fields,
        decreases head.len() - cur,
    {
        if cur >= head.len() {
            return Err(HeadError::UnterminatedHeaders);
        }
        if cur < head.len() - 1 && head[cur] == b'\r' && head[cur + 1] == b'\n' {
            break;
        }
        let end = match find_crlf(head, cur) {
            Some(i) => i,
            None => return Err(HeadError::UnterminatedHeader),
        };
        assert(end < head.len());
        if end - cur > max_field_size {
            return Err(HeadError::HeaderLineTooLong);
        }
        if head[cur] == b' ' || head[cur] == b'\t' {
            return Err(HeadError::ObsoleteFolding);
        }
        assert(end < head.len());
        let mut colon: usize = cur;
        while colon < end && head[colon] != b':'
            invariant
                cur <= colon <= end,
                end < head.len(),
            decreases end - colon,
        {
            colon = colon + 1;
        }
        if colon == end {
            return Err(HeadError::MissingColon);
        }
        let name = &head[cur..colon];
        if !valid_token(name) {
            return Err(HeadError::InvalidHeaderName);
        }
        assert(all_tchars(name@));
        assert(name.len() > 0);
        let mut vi: usize = colon + 1;
        assert(vi <= end);
        while vi < end
            invariant
                colon < vi <= end,
                end < head.len(),
                forall|j: int| colon + 1 <= j < vi ==> is_ows(head@[j])
                    || (head@[j] >= 0x20 && head@[j] != 0x7f),
            decreases end - vi,
        {
            let b = head[vi];
            if (b < 0x20 && b != b'\t') || b == 0x7f {
                return Err(HeadError::InvalidHeaderValue);
            }
            vi = vi + 1;
        }
        assert(valid_header_value(head@.subrange((colon + 1) as int, end as int)));
        let value = trim_ows_copy(&head[colon + 1..end]);
        let lname = lower_ascii(name);
        assert(valid_header_name(lname@));
        assert(header_ok((lname, value)));
        if count >= max_fields {
            return Err(HeadError::TooManyHeaders);
        }
        headers.push((lname, value));
        count = count + 1;
        assert(headers_ok(headers@));
        cur = end + 2;
    }
    assert(headers_ok(headers@));

    let mut host_idx: Option<usize> = None;
    let mut hi: usize = 0;
    while hi < headers.len()
        invariant
            hi <= headers.len(),
            match host_idx {
                Some(i) => i < headers.len(),
                None => true,
            },
        decreases headers.len() - hi,
    {
        if bytes_eq(&headers[hi].0, b"host") {
            if host_idx.is_some() {
                return Err(HeadError::DuplicateHost);
            }
            host_idx = Some(hi);
        }
        hi = hi + 1;
    }
    match host_idx {
        None => {
            if version == HttpVersion::Http11 {
                return Err(HeadError::MissingHost);
            }
        }
        Some(idx) => {
            let h = &headers[idx].1;
            if h.len() == 0 {
                return Err(HeadError::InvalidHost);
            }
            let mut hj: usize = 0;
            while hj < h.len()
                invariant hj <= h.len(),
                decreases h.len() - hj,
            {
                let b = h[hj];
                if b < 0x21 || b == 0x7f || b == b'/' || b == b'\\' || b == b'@' {
                    return Err(HeadError::InvalidHost);
                }
                hj = hj + 1;
            }
        }
    }

    let (raw_path, query) = match split_target(target) {
        Ok(pair) => pair,
        Err(e) => return Err(e),
    };

    let mut conn_idx: Option<usize> = None;
    let mut expect_idx: Option<usize> = None;
    let mut fi: usize = 0;
    while fi < headers.len()
        invariant
            fi <= headers.len(),
            match conn_idx {
                Some(i) => i < headers.len(),
                None => true,
            },
            match expect_idx {
                Some(i) => i < headers.len(),
                None => true,
            },
        decreases headers.len() - fi,
    {
        if conn_idx.is_none() && bytes_eq(&headers[fi].0, b"connection") {
            conn_idx = Some(fi);
        }
        if expect_idx.is_none() && bytes_eq(&headers[fi].0, b"expect") {
            expect_idx = Some(fi);
        }
        fi = fi + 1;
    }
    let mut keep_alive = version == HttpVersion::Http11;
    match conn_idx {
        Some(idx) => {
            keep_alive = apply_connection_tokens(&headers[idx].1, keep_alive);
        }
        None => {}
    }
    let expect_continue = match expect_idx {
        Some(idx) => {
            let (es, ee) = trim_range(&headers[idx].1);
            eq_ignore_ascii_case(&headers[idx].1[es..ee], b"100-continue")
        }
        None => false,
    };

    let framing = match request_framing(version, &headers) {
        Ok(f) => f,
        Err(e) => return Err(e),
    };

    Ok(ParsedHead {
        method: method_v,
        target: target_v,
        raw_path,
        query,
        version,
        headers,
        framing,
        keep_alive,
        expect_continue,
    })
}

// ---------------------------------------------------------------------------
// Performance-path safety predicates
// ---------------------------------------------------------------------------

/// Whether a full-file read may be served from an mmap rather than copied into
/// a user buffer.
///
/// The length check prevents mapping past EOF.  The permission check refuses
/// to map a file that the server's effective uid could truncate: an mmap of a
/// file truncated concurrently can raise SIGBUS, so files writable by the
/// server fall back to a copied read.
pub open spec fn mmap_read_ok(
    file_len: u64,
    requested: u64,
    file_uid: u32,
    euid: u32,
    mode: u32,
) -> bool {
    requested <= file_len
        && !((file_uid == euid && mode & 0o200 != 0)
            || mode & 0o020 != 0
            || mode & 0o002 != 0)
}

pub fn mmap_read_allowed(
    file_len: u64,
    requested: u64,
    file_uid: u32,
    euid: u32,
    mode: u32,
) -> (ok: bool)
    ensures ok == mmap_read_ok(file_len, requested, file_uid, euid, mode),
{
    requested <= file_len
        && !((file_uid == euid && mode & 0o200 != 0)
            || mode & 0o020 != 0
            || mode & 0o002 != 0)
}

/// A response body is compressed only while it stays within the fixed
/// in-memory compression cap.  Larger bodies are passed through unchanged,
/// which removes the "compress forever after disconnect" resource class.
pub fn compression_body_admit(len: u64, limit: u64) -> (ok: bool)
    ensures ok == (len <= limit),
{
    len <= limit
}

/// Admission for one connection/worker slot.  The caller still performs the
/// atomic reservation; this is the single bound predicate used by that path.
pub fn connection_admit(active: u64, max: u64) -> (ok: bool)
    ensures ok == (active < max),
{
    active < max
}

/// Bound check for a length-prefixed CGI worker protocol field.
pub fn cgi_field_len_ok(len: u32, limit: u32) -> (ok: bool)
    ensures ok == (len <= limit),
{
    len <= limit
}

/// Number of bytes to hand to the next HTTP/2 DATA send.  The result is
/// bounded by both inputs, and is nonzero whenever both inputs are nonzero, so
/// the streaming loop always makes progress.
pub fn h2_batch_len(remaining: u64, batch: u64) -> (n: u64)
    ensures
        n <= remaining,
        n <= batch,
        remaining > 0 && batch > 0 ==> n > 0,
{
    if remaining < batch {
        remaining
    } else {
        batch
    }
}

// ---------------------------------------------------------------------------
// CGI environment admission
// ---------------------------------------------------------------------------

/// Regex dialect admission for configuration and expression patterns.  The
/// externally supplied regex engine is assumed to implement the accepted
/// regular subset; this guard rejects constructs whose Apache/PCRE meaning
/// cannot be represented by the Rust regex engine (backreferences and
/// look-around), plus control bytes and oversized patterns.
pub open spec fn regex_byte_ok(b: u8) -> bool {
    b >= 0x20 && b != 0x7f
}

pub open spec fn regex_unsupported_at(pattern: Seq<u8>, i: int) -> bool {
    if i < 0 || i >= pattern.len() {
        false
    } else if i + 1 < pattern.len()
        && pattern[i] == b'\\'
        && pattern[i + 1] >= b'1'
        && pattern[i + 1] <= b'9'
    {
        true
    } else if i + 2 < pattern.len() && pattern[i] == b'(' && pattern[i + 1] == b'?'
        && (pattern[i + 2] == b'=' || pattern[i + 2] == b'!')
    {
        true
    } else if i + 3 < pattern.len() && pattern[i] == b'('
        && pattern[i + 1] == b'?' && pattern[i + 2] == b'<'
        && (pattern[i + 3] == b'=' || pattern[i + 3] == b'!')
    {
        true
    } else if i + 2 < pattern.len() && pattern[i] == b'(' && pattern[i + 1] == b'?'
        && (pattern[i + 2] == b'>' || pattern[i + 2] == b'(')
    {
        true
    } else {
        false
    }
}

pub open spec fn regex_dialect_admit_spec(pattern: Seq<u8>) -> bool {
    pattern.len() <= 65536
        && forall|i: int| 0 <= i < pattern.len() ==> regex_byte_ok(pattern[i])
        && forall|i: int| 0 <= i < pattern.len() ==> !regex_unsupported_at(pattern, i)
}

fn regex_byte_ok_exec(b: u8) -> (ok: bool)
    ensures ok == regex_byte_ok(b),
{
    b >= 0x20 && b != 0x7f
}

fn regex_unsupported_at_exec(pattern: &[u8], i: usize) -> (unsupported: bool)
    requires i < pattern.len(),
    ensures unsupported == regex_unsupported_at(pattern@, i as int),
{
    if pattern.len() - i >= 2
        && pattern[i] == b'\\'
        && pattern[i + 1] >= b'1'
        && pattern[i + 1] <= b'9'
    {
        true
    } else if pattern.len() - i >= 3
        && pattern[i] == b'('
        && pattern[i + 1] == b'?'
        && (pattern[i + 2] == b'=' || pattern[i + 2] == b'!')
    {
        true
    } else if pattern.len() - i >= 4
        && pattern[i] == b'('
        && pattern[i + 1] == b'?'
        && pattern[i + 2] == b'<'
        && (pattern[i + 3] == b'=' || pattern[i + 3] == b'!')
    {
        true
    } else if pattern.len() - i >= 3
        && pattern[i] == b'('
        && pattern[i + 1] == b'?'
        && (pattern[i + 2] == b'>' || pattern[i + 2] == b'(')
    {
        true
    } else {
        false
    }
}

pub fn regex_dialect_admit(pattern: &[u8]) -> (admit: bool)
    ensures admit == regex_dialect_admit_spec(pattern@),
{
    if pattern.len() > 65536 {
        return false;
    }
    let mut i: usize = 0;
    while i < pattern.len()
        invariant
            i <= pattern.len(),
            forall|j: int| 0 <= j < i ==> regex_byte_ok(pattern@[j]),
            forall|j: int| 0 <= j < i ==> !regex_unsupported_at(pattern@, j),
        decreases pattern.len() - i,
    {
        if !regex_byte_ok_exec(pattern[i]) {
            assert(!regex_dialect_admit_spec(pattern@));
            return false;
        }
        if regex_unsupported_at_exec(pattern, i) {
            assert(!regex_dialect_admit_spec(pattern@));
            return false;
        }
        i = i + 1;
    }
    true
}

/// A configured/rewrite environment entry may pass only when its name is a
/// valid non-reserved environment key.  Calculated CGI variables and `HTTP_*`
/// request-derived variables are classified by the caller and cannot be
/// overridden (CVE-2025-65082).
pub fn cgi_env_entry_admit(
    key_valid: bool,
    reserved: bool,
) -> (admit: bool)
    ensures admit == (key_valid && !reserved),
{
    key_valid && !reserved
}

// ---------------------------------------------------------------------------
// HTTP cache lookup policy
// ---------------------------------------------------------------------------

/// One cache lookup is admissible only when the key and policy match, the
/// stored `Vary` values match the current request, and the entry is fresh.
/// This is the security decision consumed by the runtime cache lookup.
pub fn cache_lookup_admit(
    key_match: bool,
    policy_match: bool,
    vary_match: bool,
    expires: i64,
    now: i64,
) -> (hit: bool)
    ensures hit == (key_match && policy_match && vary_match && now < expires),
{
    key_match && policy_match && vary_match && now < expires
}

// ---------------------------------------------------------------------------
// Proxy target identity
// ---------------------------------------------------------------------------

/// Canonical, un-hashed identity of one outbound proxy target.  Host and path
/// are length-delimited by a NUL separator; the runtime host/path validators
/// exclude NUL.  This is the exact key used for grant binding.
pub open spec fn proxy_target_key_spec(
    host: Seq<u8>,
    port: u16,
    tls: bool,
    path: Seq<u8>,
) -> Seq<u8> {
    seq![
        if tls { 1u8 } else { 0u8 },
        (port / 256) as u8,
        (port % 256) as u8
    ] + host + seq![0u8] + path
}

pub fn proxy_target_key(
    host: &[u8],
    port: u16,
    tls: bool,
    path: &[u8],
) -> (out: Vec<u8>)
    ensures out@ == proxy_target_key_spec(host@, port, tls, path@),
{
    let mut out: Vec<u8> = Vec::new();
    out.push(if tls { 1 } else { 0 });
    out.push((port / 256) as u8);
    out.push((port % 256) as u8);
    out.extend_from_slice(host);
    out.push(0);
    out.extend_from_slice(path);
    out
}

// ---------------------------------------------------------------------------
// Authorization combination
// ---------------------------------------------------------------------------

/// Three-valued result of evaluating an authorization provider or tree.
/// `Neutral` is a method-limited section that does not apply.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PolicyResult {
    Granted,
    Denied,
    AuthRequired,
    Neutral,
}

pub open spec fn combine_and_spec(a: PolicyResult, b: PolicyResult) -> PolicyResult {
    match (a, b) {
        (PolicyResult::Denied, _) => PolicyResult::Denied,
        (_, PolicyResult::Denied) => PolicyResult::Denied,
        (PolicyResult::AuthRequired, _) => PolicyResult::AuthRequired,
        (_, PolicyResult::AuthRequired) => PolicyResult::AuthRequired,
        (PolicyResult::Granted, _) => PolicyResult::Granted,
        (_, PolicyResult::Granted) => PolicyResult::Granted,
        _ => PolicyResult::Neutral,
    }
}

pub open spec fn combine_or_spec(a: PolicyResult, b: PolicyResult) -> PolicyResult {
    match (a, b) {
        (PolicyResult::Granted, _) => PolicyResult::Granted,
        (_, PolicyResult::Granted) => PolicyResult::Granted,
        (PolicyResult::AuthRequired, _) => PolicyResult::AuthRequired,
        (_, PolicyResult::AuthRequired) => PolicyResult::AuthRequired,
        (PolicyResult::Denied, _) => PolicyResult::Denied,
        (_, PolicyResult::Denied) => PolicyResult::Denied,
        _ => PolicyResult::Neutral,
    }
}

/// `<RequireAll>` combination.
pub fn combine_and(a: PolicyResult, b: PolicyResult) -> (r: PolicyResult)
    ensures r == combine_and_spec(a, b)
{
    match (a, b) {
        (PolicyResult::Denied, _) => PolicyResult::Denied,
        (_, PolicyResult::Denied) => PolicyResult::Denied,
        (PolicyResult::AuthRequired, _) => PolicyResult::AuthRequired,
        (_, PolicyResult::AuthRequired) => PolicyResult::AuthRequired,
        (PolicyResult::Granted, _) => PolicyResult::Granted,
        (_, PolicyResult::Granted) => PolicyResult::Granted,
        _ => PolicyResult::Neutral,
    }
}

/// `<RequireAny>` combination.
pub fn combine_or(a: PolicyResult, b: PolicyResult) -> (r: PolicyResult)
    ensures r == combine_or_spec(a, b)
{
    match (a, b) {
        (PolicyResult::Granted, _) => PolicyResult::Granted,
        (_, PolicyResult::Granted) => PolicyResult::Granted,
        (PolicyResult::AuthRequired, _) => PolicyResult::AuthRequired,
        (_, PolicyResult::AuthRequired) => PolicyResult::AuthRequired,
        (PolicyResult::Denied, _) => PolicyResult::Denied,
        (_, PolicyResult::Denied) => PolicyResult::Denied,
        _ => PolicyResult::Neutral,
    }
}

/// A `<RequireNone>` group cannot grant authorization.  A granted child
/// becomes denied; denied/auth-required children are neutral.
pub fn require_none_result(r: PolicyResult) -> (out: PolicyResult)
    ensures out != PolicyResult::Granted
{
    match r {
        PolicyResult::Granted => PolicyResult::Denied,
        PolicyResult::Denied | PolicyResult::AuthRequired => PolicyResult::Neutral,
        PolicyResult::Neutral => PolicyResult::Neutral,
    }
}

proof fn combine_and_commutative(a: PolicyResult, b: PolicyResult)
    ensures combine_and_spec(a, b) == combine_and_spec(b, a)
{
}

proof fn combine_or_commutative(a: PolicyResult, b: PolicyResult)
    ensures combine_or_spec(a, b) == combine_or_spec(b, a)
{
}


// ---------------------------------------------------------------------------
// Configuration phase and access-file interleaving plan
// ---------------------------------------------------------------------------

/// Canonical stage order.  A `Walk { access }` step applies the literal
/// `<Directory>` rules for the next ancestor directory and, when `access` is
/// true, immediately merges that directory's top-level `.htaccess` scope.  The
/// per-directory interleaving `Directory(i); access-file(i)` is therefore one
/// indivisible step.  Files/Location are deferred until all directory steps
/// finish; conditions are last.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccessStep {
    Walk { access: bool },
    DirectoryMatch,
    ConfigFiles,
    AccessFiles,
    ConfigLocation,
    ConfigConditions,
    AccessConditions,
}

pub open spec fn access_suffix() -> Seq<AccessStep> {
    seq![
        AccessStep::DirectoryMatch,
        AccessStep::ConfigFiles,
        AccessStep::AccessFiles,
        AccessStep::ConfigLocation,
        AccessStep::ConfigConditions,
        AccessStep::AccessConditions,
    ]
}

pub open spec fn access_walk_plan_from(
    present: Seq<bool>,
    start: int,
) -> Seq<AccessStep>
    decreases present.len() - start,
{
    if start >= present.len() {
        Seq::empty()
    } else {
        seq![AccessStep::Walk { access: present[start] }]
            + access_walk_plan_from(present, start + 1)
    }
}

pub open spec fn access_walk_plan(present: Seq<bool>) -> Seq<AccessStep> {
    access_walk_plan_from(present, 0)
}

pub open spec fn access_plan(present: Seq<bool>) -> Seq<AccessStep> {
    access_walk_plan(present) + access_suffix()
}

pub open spec fn is_walk(step: AccessStep) -> bool {
    match step {
        AccessStep::Walk { .. } => true,
        _ => false,
    }
}

pub fn access_walk_plan_exec_from(
    present: &[bool],
    start: usize,
) -> (out: Vec<AccessStep>)
    requires start <= present.len(),
    ensures out@ == access_walk_plan_from(present@, start as int),
    decreases present.len() - start,
{
    if start >= present.len() {
        Vec::new()
    } else {
        let mut out: Vec<AccessStep> = Vec::new();
        out.push(AccessStep::Walk { access: present[start] });
        let mut rest = access_walk_plan_exec_from(present, start + 1);
        out.append(&mut rest);
        assert(out@ == seq![AccessStep::Walk { access: present@[start as int] }]
            + access_walk_plan_from(present@, start as int + 1));
        out
    }
}

pub fn access_walk_plan_exec(present: &[bool]) -> (out: Vec<AccessStep>)
    ensures out@ == access_walk_plan(present@)
{
    access_walk_plan_exec_from(present, 0)
}

pub fn access_plan_exec(present: &[bool]) -> (out: Vec<AccessStep>)
    ensures out@ == access_plan(present@)
{
    let mut out = access_walk_plan_exec(present);
    out.push(AccessStep::DirectoryMatch);
    out.push(AccessStep::ConfigFiles);
    out.push(AccessStep::AccessFiles);
    out.push(AccessStep::ConfigLocation);
    out.push(AccessStep::ConfigConditions);
    out.push(AccessStep::AccessConditions);
    assert(out@ == access_walk_plan(present@) + access_suffix());
    out
}

proof fn lemma_access_walk_plan_length_from(present: Seq<bool>, start: int)
    requires 0 <= start <= present.len(),
    ensures access_walk_plan_from(present, start).len() == present.len() - start,
    decreases present.len() - start,
{
    if start >= present.len() {
    } else {
        lemma_access_walk_plan_length_from(present, start + 1);
    }
}

proof fn lemma_access_walk_plan_all_walk_from(present: Seq<bool>, start: int)
    requires 0 <= start <= present.len(),
    ensures
        forall|k: int|
            0 <= k < access_walk_plan_from(present, start).len() ==>
                #[trigger] is_walk(access_walk_plan_from(present, start)[k]),
    decreases present.len() - start,
{
    if start >= present.len() {
    } else {
        lemma_access_walk_plan_all_walk_from(present, start + 1);
        assert(access_walk_plan_from(present, start)
            == seq![AccessStep::Walk { access: present[start] }]
                + access_walk_plan_from(present, start + 1));
        assert forall|k: int|
            0 <= k < access_walk_plan_from(present, start).len() ==>
                #[trigger] is_walk(access_walk_plan_from(present, start)[k])
        by {
            if 0 <= k < access_walk_plan_from(present, start).len() {
                if k == 0 {
                } else {
                    lemma_access_walk_plan_length_from(present, start + 1);
                    assert(access_walk_plan_from(present, start).len()
                        == 1 + access_walk_plan_from(present, start + 1).len());
                    assert(k - 1 < access_walk_plan_from(present, start + 1).len());
                    assert(access_walk_plan_from(present, start)[k]
                        == access_walk_plan_from(present, start + 1)[k - 1]);
                }
            }
        }
    }
}

/// Interleaver theorem:
///
/// 1. the walk plan has exactly one step per ancestor directory;
/// 2. every walk step precedes the deferred phase suffix;
/// 3. the suffix is exactly
///    `DirectoryMatch, ConfigFiles, AccessFiles, Location, config If, access If`.
///
/// Step (1) pairs each `Walk` with the root-to-leaf directory list.  The
/// per-directory `Directory; access scope` order is inside the step, so it
/// cannot be reordered by construction.
pub proof fn access_plan_interleaves(present: Seq<bool>)
    ensures
        access_walk_plan(present).len() == present.len(),
        forall|k: int|
            0 <= k < access_walk_plan(present).len() ==>
                #[trigger] is_walk(access_walk_plan(present)[k]),
        access_plan(present) == access_walk_plan(present) + access_suffix(),
        access_suffix().len() == 6,
{
    lemma_access_walk_plan_length_from(present, 0);
    lemma_access_walk_plan_all_walk_from(present, 0);
    assert(access_suffix().len() == 6);
}


// ---------------------------------------------------------------------------
// Merge-phase helpers used by the runtime
// ---------------------------------------------------------------------------

/// How a child `Require` policy combines with an inherited policy.  This is
/// the decision `Scope::merge` makes from `AuthMerging`; keeping it in the
/// verified crate makes the security-relevant branch explicit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthMergeKind {
    Replace,
    And,
    Or,
}

pub open spec fn auth_merge_kind_spec(
    merging_and: bool,
    merging_or: bool,
    has_parent: bool,
) -> AuthMergeKind {
    if has_parent && merging_and {
        AuthMergeKind::And
    } else if has_parent && merging_or {
        AuthMergeKind::Or
    } else {
        AuthMergeKind::Replace
    }
}

pub fn auth_merge_kind(
    merging_and: bool,
    merging_or: bool,
    has_parent: bool,
) -> (out: AuthMergeKind)
    ensures out == auth_merge_kind_spec(merging_and, merging_or, has_parent)
{
    if has_parent && merging_and {
        AuthMergeKind::And
    } else if has_parent && merging_or {
        AuthMergeKind::Or
    } else {
        AuthMergeKind::Replace
    }
}

proof fn auth_merge_kind_properties(
    merging_and: bool,
    merging_or: bool,
    has_parent: bool,
)
    ensures
        auth_merge_kind_spec(merging_and, merging_or, has_parent)
                == AuthMergeKind::And
            ==> has_parent && merging_and,
        auth_merge_kind_spec(merging_and, merging_or, has_parent)
                == AuthMergeKind::Or
            ==> has_parent && merging_or,
        !has_parent
            ==> auth_merge_kind_spec(merging_and, merging_or, has_parent)
                == AuthMergeKind::Replace,
{
}

pub enum AccessRuleClass {
    Conditional,
    Files,
    Other,
}

pub open spec fn access_rule_class_spec(
    has_condition: bool,
    normal_branch: bool,
    files_rule: bool,
) -> AccessRuleClass {
    if has_condition || !normal_branch {
        AccessRuleClass::Conditional
    } else if files_rule {
        AccessRuleClass::Files
    } else {
        AccessRuleClass::Other
    }
}

/// Section kinds used by the recursive configuration parser.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfigSectionKind {
    Server,
    VirtualHost,
    Directory,
    DirectoryMatch,
    Location,
    Files,
    Proxy,
    Require,
    Conditional,
}

pub open spec fn config_section_nesting_allowed_spec(
    parent: ConfigSectionKind,
    child: ConfigSectionKind,
) -> bool {
    use ConfigSectionKind::*;
    match (parent, child) {
        (Server, VirtualHost) => true,
        (_, VirtualHost) => false,
        (Directory | DirectoryMatch | Location | Files | Proxy | Require, Directory | DirectoryMatch) => false,
        (Directory | DirectoryMatch | Location | Files | Proxy | Require, Location) => false,
        (Conditional, Directory | DirectoryMatch | Location | Proxy) => false,
        (Location | Files | Proxy | Require, Files) => false,
        (Directory | DirectoryMatch | Location | Files | Proxy | Require, Proxy) => false,
        (Require, _) => false,
        _ => true,
    }
}

/// Apache rejects most cross-section nesting.  This is the verified context
/// transition used by the configuration compiler; a rejected child section
/// cannot silently acquire a different scope interpretation.
pub fn config_section_nesting_allowed(
    parent: ConfigSectionKind,
    child: ConfigSectionKind,
) -> (allowed: bool)
    ensures allowed == config_section_nesting_allowed_spec(parent, child),
{
    use ConfigSectionKind::*;
    match (parent, child) {
        (Server, VirtualHost) => true,
        (_, VirtualHost) => false,
        (Directory | DirectoryMatch | Location | Files | Proxy | Require, Directory | DirectoryMatch) => false,
        (Directory | DirectoryMatch | Location | Files | Proxy | Require, Location) => false,
        (Conditional, Directory | DirectoryMatch | Location | Proxy) => false,
        (Location | Files | Proxy | Require, Files) => false,
        (Directory | DirectoryMatch | Location | Files | Proxy | Require, Proxy) => false,
        (Require, _) => false,
        _ => true,
    }
}

/// Disposition for a directive that was not handled by the parser's main
/// match.  Security-sensitive names fail closed even in compatibility mode;
/// a recognised but unimplemented module directive is a warning, and an
/// unknown directive is a strict-mode error or a compatibility warning.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DirectiveDisposition {
    FailClosedSecurity,
    WarnKnown,
    FailClosedStrict,
    WarnUnknown,
}

pub open spec fn directive_disposition_spec(
    security: bool,
    known: bool,
    strict: bool,
) -> DirectiveDisposition {
    if security {
        DirectiveDisposition::FailClosedSecurity
    } else if known {
        DirectiveDisposition::WarnKnown
    } else if strict {
        DirectiveDisposition::FailClosedStrict
    } else {
        DirectiveDisposition::WarnUnknown
    }
}

pub fn directive_disposition(
    security: bool,
    known: bool,
    strict: bool,
) -> (disposition: DirectiveDisposition)
    ensures disposition == directive_disposition_spec(security, known, strict),
{
    if security {
        DirectiveDisposition::FailClosedSecurity
    } else if known {
        DirectiveDisposition::WarnKnown
    } else if strict {
        DirectiveDisposition::FailClosedStrict
    } else {
        DirectiveDisposition::WarnUnknown
    }
}

/// Translation slot for a parsed `.htaccess` rule.  The parser supplies the
/// three syntactic facts; this model fixes where the rule must be deferred.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccessLayerSlot {
    Conditional,
    Files,
    TopLevel,
}

pub open spec fn access_layer_slot_spec(
    has_condition: bool,
    normal_branch: bool,
    files_rule: bool,
) -> AccessLayerSlot {
    if has_condition || !normal_branch {
        AccessLayerSlot::Conditional
    } else if files_rule {
        AccessLayerSlot::Files
    } else {
        AccessLayerSlot::TopLevel
    }
}

pub fn access_layer_slot(
    has_condition: bool,
    normal_branch: bool,
    files_rule: bool,
) -> (slot: AccessLayerSlot)
    ensures slot == access_layer_slot_spec(has_condition, normal_branch, files_rule),
{
    if has_condition || !normal_branch {
        AccessLayerSlot::Conditional
    } else if files_rule {
        AccessLayerSlot::Files
    } else {
        AccessLayerSlot::TopLevel
    }
}

/// Classify a parsed `.htaccess` rule for the layer plan.  Conditions and
/// non-normal branches always go to the deferred conditional phase; Files
/// rules go to the deferred Files phase; everything else is handled by the
/// layer's top-level scope.
pub fn classify_access_rule(
    has_condition: bool,
    normal_branch: bool,
    files_rule: bool,
) -> (out: AccessRuleClass)
    ensures out == access_rule_class_spec(has_condition, normal_branch, files_rule)
{
    if has_condition || !normal_branch {
        AccessRuleClass::Conditional
    } else if files_rule {
        AccessRuleClass::Files
    } else {
        AccessRuleClass::Other
    }
}


/// Apply one `Options` change.  Operation codes are stable and match the
/// runtime enum: 0 = Set, 1 = Add, 2 = Remove.  Only `Add` can introduce bits,
/// and it can introduce only bits present in `mask`; `Remove` clears only
/// `mask`; `Set` replaces the whole value.
pub open spec fn options_apply_spec(bits: u32, op: u8, mask: u32) -> u32 {
    if op == 0 {
        mask
    } else if op == 1 {
        bits | mask
    } else {
        bits & !mask
    }
}

pub fn options_apply(bits: u32, op: u8, mask: u32) -> (out: u32)
    ensures out == options_apply_spec(bits, op, mask)
{
    if op == 0 {
        mask
    } else if op == 1 {
        bits | mask
    } else {
        bits & !mask
    }
}




/// Truthiness of an expression value.  The evaluator's leaves may consult
/// regex/filesystem/request state, but the value-to-boolean step is fixed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExprValueKind {
    Bool,
    Int,
    Str,
    List,
}

pub open spec fn expr_value_truthy_spec(
    kind: ExprValueKind,
    boolean: bool,
    integer: i64,
    length: u64,
) -> bool {
    match kind {
        ExprValueKind::Bool => boolean,
        ExprValueKind::Int => integer != 0,
        ExprValueKind::Str => length > 0,
        ExprValueKind::List => length > 0,
    }
}

pub fn expr_value_truthy(
    kind: ExprValueKind,
    boolean: bool,
    integer: i64,
    length: u64,
) -> (truthy: bool)
    ensures truthy == expr_value_truthy_spec(kind, boolean, integer, length),
{
    match kind {
        ExprValueKind::Bool => boolean,
        ExprValueKind::Int => integer != 0,
        ExprValueKind::Str => length > 0,
        ExprValueKind::List => length > 0,
    }
}

/// Fold an Apache rewrite-condition chain.  `matches[i]` is the predicate
/// result and `ors[i]` is the `[OR]` flag.  A run of OR-linked conditions is
/// ORed together; each completed run is ANDed into the overall result.
pub open spec fn cond_chain_from(
    matches: Seq<bool>,
    ors: Seq<bool>,
    i: int,
    overall: bool,
    group: bool,
    in_group: bool,
) -> bool
    decreases matches.len() - i,
{
    if i >= matches.len() {
        if in_group { overall && group } else { overall }
    } else {
        let next_group = if in_group { group || matches[i] } else { matches[i] };
        if ors[i] {
            cond_chain_from(matches, ors, i + 1, overall, next_group, true)
        } else {
            cond_chain_from(matches, ors, i + 1, overall && next_group, false, false)
        }
    }
}

pub open spec fn cond_chain_spec(matches: Seq<bool>, ors: Seq<bool>) -> bool {
    cond_chain_from(matches, ors, 0, true, false, false)
}

fn cond_chain_rec(
    matches: &[bool],
    ors: &[bool],
    i: usize,
    overall: bool,
    group: bool,
    in_group: bool,
) -> (out: bool)
    requires
        matches.len() == ors.len(),
        i <= matches.len(),
    ensures
        out == cond_chain_from(matches@, ors@, i as int, overall, group, in_group),
    decreases matches.len() - i,
{
    if i >= matches.len() {
        if in_group { overall && group } else { overall }
    } else {
        let next_group = if in_group { group || matches[i] } else { matches[i] };
        if ors[i] {
            cond_chain_rec(matches, ors, i + 1, overall, next_group, true)
        } else {
            cond_chain_rec(matches, ors, i + 1, overall && next_group, false, false)
        }
    }
}

pub fn cond_chain_eval(matches: &[bool], ors: &[bool]) -> (out: bool)
    requires matches.len() == ors.len(),
    ensures out == cond_chain_spec(matches@, ors@),
{
    cond_chain_rec(matches, ors, 0, true, false, false)
}

proof fn classify_access_rule_properties(
    has_condition: bool,
    normal_branch: bool,
    files_rule: bool,
)
    ensures
        (has_condition || !normal_branch)
            ==> access_rule_class_spec(has_condition, normal_branch, files_rule)
                == AccessRuleClass::Conditional,
        (!has_condition && normal_branch && files_rule)
            ==> access_rule_class_spec(has_condition, normal_branch, files_rule)
                == AccessRuleClass::Files,
        (!has_condition && normal_branch && !files_rule)
            ==> access_rule_class_spec(has_condition, normal_branch, files_rule)
                == AccessRuleClass::Other,
{
}

/// Scalar child-overrides-parent merge used for optional scope fields.
pub fn option_child_wins<T: Copy + PartialEq>(
    parent: Option<T>,
    child: Option<T>,
) -> (out: Option<T>)
    ensures out == (if child.is_some() { child } else { parent })
{
    if child.is_some() {
        child
    } else {
        parent
    }
}




// ---------------------------------------------------------------------------
// Virtual-host name matching
// ---------------------------------------------------------------------------

/// Case-insensitive host suffix at a DNS label boundary.
pub open spec fn host_suffix_spec(host: Seq<u8>, suffix: Seq<u8>) -> bool {
    host.len() >= suffix.len()
        && suffix.len() > 0
        && eq_ignore_ascii_case_spec(
            host.subrange((host.len() - suffix.len()) as int, host.len() as int),
            suffix,
        )
        && (host.len() == suffix.len() || host[host.len() - suffix.len() - 1] == b'.')
}

pub open spec fn host_pattern_matches_spec(host: Seq<u8>, pattern: Seq<u8>) -> bool {
    if pattern.len() >= 2 && pattern[0] == b'*' && pattern[1] == b'.' {
        let rest = pattern.subrange(2, pattern.len() as int);
        eq_ignore_ascii_case_spec(host, rest) || host_suffix_spec(host, rest)
    } else if pattern.len() >= 1 && pattern[0] == b'.' {
        let rest = pattern.subrange(1, pattern.len() as int);
        eq_ignore_ascii_case_spec(host, rest) || host_suffix_spec(host, rest)
    } else {
        eq_ignore_ascii_case_spec(host, pattern)
    }
}

pub fn host_suffix_matches(host: &[u8], suffix: &[u8]) -> (ok: bool)
    ensures ok == host_suffix_spec(host@, suffix@)
{
    if suffix.is_empty() || host.len() < suffix.len() {
        return false;
    }
    let start = host.len() - suffix.len();
    if !eq_ignore_ascii_case(&host[start..], suffix) {
        return false;
    }
    if start == 0 {
        true
    } else {
        host[start - 1] == b'.'
    }
}

/// Exact host or `*.suffix` / `.suffix` matching, with ASCII case folding and
/// a DNS-label boundary.  The caller trims trailing dots and handles the
/// Apache `~regex` form separately.
pub fn host_pattern_matches(host: &[u8], pattern: &[u8]) -> (ok: bool)
    ensures ok == host_pattern_matches_spec(host@, pattern@)
{
    if pattern.len() >= 2 && pattern[0] == b'*' && pattern[1] == b'.' {
        let rest = &pattern[2..];
        if eq_ignore_ascii_case(host, rest) {
            true
        } else {
            host_suffix_matches(host, rest)
        }
    } else if pattern.len() >= 1 && pattern[0] == b'.' {
        let rest = &pattern[1..];
        if eq_ignore_ascii_case(host, rest) {
            true
        } else {
            host_suffix_matches(host, rest)
        }
    } else {
        eq_ignore_ascii_case(host, pattern)
    }
}


pub open spec fn ipv4_in_net_spec(ip: u32, net: u32, bits: u8) -> bool {
    bits <= 32 && (if bits == 0 {
        true
    } else {
        let mask = u32::MAX << (32 - bits);
        (ip & mask) == (net & mask)
    })
}

pub fn ipv4_in_net(ip: u32, net: u32, bits: u8) -> (out: bool)
    ensures out == ipv4_in_net_spec(ip, net, bits)
{
    if bits > 32 {
        false
    } else if bits == 0 {
        true
    } else {
        let mask = u32::MAX << (32 - bits);
        (ip & mask) == (net & mask)
    }
}


pub open spec fn ipv6_in_net_spec(ip: u128, net: u128, bits: u8) -> bool {
    bits <= 128 && (if bits == 0 {
        true
    } else {
        let mask = u128::MAX << (128 - bits);
        (ip & mask) == (net & mask)
    })
}

pub fn ipv6_in_net(ip: u128, net: u128, bits: u8) -> (out: bool)
    ensures out == ipv6_in_net_spec(ip, net, bits)
{
    if bits > 128 {
        false
    } else if bits == 0 {
        true
    } else {
        let mask = u128::MAX << (128 - bits);
        (ip & mask) == (net & mask)
    }
}


/// Index of the first untrusted address in a right-to-left client chain.
pub open spec fn first_untrusted_spec(flags: Seq<bool>) -> Option<int>
    decreases flags.len(),
{
    if flags.len() == 0 {
        None
    } else if !flags[0] {
        Some(0)
    } else {
        match first_untrusted_spec(flags.drop_first()) {
            None => None,
            Some(i) => Some(i + 1),
        }
    }
}

pub fn first_untrusted_index(flags: &[bool]) -> (out: Option<usize>)
    ensures
        match out {
            None => first_untrusted_spec(flags@) == None,
            Some(i) => {
                &&& first_untrusted_spec(flags@) == Some(i as int)
                &&& i < flags.len()
                &&& !flags@[i as int]
                &&& forall|j: int| 0 <= j < i ==> flags@[j]
            }
        }
    decreases flags.len(),
{
    if flags.len() == 0 {
        assert(first_untrusted_spec(flags@) == None);
        None
    } else if !flags[0] {
        assert(first_untrusted_spec(flags@) == Some(0));
        Some(0)
    } else {
        let rest = &flags[1..];
        assert(flags@ == seq![flags@[0]] + rest@);
        match first_untrusted_index(rest) {
            None => {
                assert(first_untrusted_spec(flags@) == None);
                None
            }
            Some(i) => {
                assert(first_untrusted_spec(flags@) == Some(i as int + 1));
                Some(i + 1)
            }
        }
    }
}


/// First true flag, used for deterministic vhost candidate selection.
pub open spec fn first_true_spec(flags: Seq<bool>) -> Option<int>
    decreases flags.len(),
{
    if flags.len() == 0 {
        None
    } else if flags[0] {
        Some(0)
    } else {
        match first_true_spec(flags.drop_first()) {
            None => None,
            Some(i) => Some(i + 1),
        }
    }
}

pub fn first_true_index(flags: &[bool]) -> (out: Option<usize>)
    ensures
        match out {
            None => first_true_spec(flags@) == None,
            Some(i) => {
                &&& first_true_spec(flags@) == Some(i as int)
                &&& i < flags.len()
                &&& flags@[i as int]
                &&& forall|j: int| 0 <= j < i ==> !flags@[j]
            }
        }
    decreases flags.len(),
{
    if flags.len() == 0 {
        assert(first_true_spec(flags@) == None);
        None
    } else if flags[0] {
        assert(first_true_spec(flags@) == Some(0));
        Some(0)
    } else {
        let rest = &flags[1..];
        assert(flags@ == seq![flags@[0]] + rest@);
        match first_true_index(rest) {
            None => {
                assert(first_true_spec(flags@) == None);
                None
            }
            Some(i) => {
                assert(first_true_spec(flags@) == Some(i as int + 1));
                Some(i + 1)
            }
        }
    }
}


/// Child-overrides-parent for fields that are not `Copy`.  The value clone
/// itself is the Rust standard-library primitive; the verified contract is
/// that presence is preserved exactly, so a child field can never be lost by
/// the merge decision.
pub fn option_child_presence<T: Clone>(
    parent: &Option<T>,
    child: &Option<T>,
) -> (out: Option<T>)
    ensures
        child.is_some() ==> out.is_some(),
        child.is_none() ==> (out.is_some() == parent.is_some()),
{
    if child.is_some() {
        child.clone()
    } else {
        parent.clone()
    }
}


// ---------------------------------------------------------------------------
// TLS listener client-certificate policy identity
// ---------------------------------------------------------------------------

/// Decide whether two virtual hosts may share one TLS listener.  Rustls has
/// one client-certificate verifier per `ServerConfig`, so a listener may only
/// be shared by vhosts with identical verification mode and CA-file identity.
/// The mode is encoded by the caller (including the absent/present
/// distinction); the CA is compared by exact bytes.  Chain validation itself
/// remains the external TLS/Rustls contract.
pub fn tls_client_policy_equal(
    mode_a: u8,
    has_ca_a: bool,
    ca_a: &[u8],
    mode_b: u8,
    has_ca_b: bool,
    ca_b: &[u8],
) -> (equal: bool)
    ensures
        equal == (mode_a == mode_b && has_ca_a == has_ca_b && ca_a@ == ca_b@),
{
    if mode_a != mode_b || has_ca_a != has_ca_b || ca_a.len() != ca_b.len() {
        false
    } else {
        bytes_eq(ca_a, ca_b)
    }
}

// ---------------------------------------------------------------------------
// Configuration front-end IR
// ---------------------------------------------------------------------------

/// The three pure line kinds produced by the configuration tokenizer.  This
/// is the Verus-side anchor for the parser IR; argument payloads and concrete
/// directive parsing remain in the server front-end until the recursive
/// section parser is migrated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfigLineKind {
    Directive,
    SectionStart,
    SectionEnd,
}

pub open spec fn config_line_kind_spec(
    starts_with_end_tag: bool,
    starts_with_start_tag: bool,
) -> ConfigLineKind {
    if starts_with_end_tag {
        ConfigLineKind::SectionEnd
    } else if starts_with_start_tag {
        ConfigLineKind::SectionStart
    } else {
        ConfigLineKind::Directive
    }
}

pub fn config_line_kind(
    starts_with_end_tag: bool,
    starts_with_start_tag: bool,
) -> (kind: ConfigLineKind)
    ensures kind == config_line_kind_spec(starts_with_end_tag, starts_with_start_tag),
{
    if starts_with_end_tag {
        ConfigLineKind::SectionEnd
    } else if starts_with_start_tag {
        ConfigLineKind::SectionStart
    } else {
        ConfigLineKind::Directive
    }
}

// ---------------------------------------------------------------------------
// Container-field merge model
// ---------------------------------------------------------------------------

/// Structural append used by every container/list field in `Scope::merge`.
/// The concrete elements are cloned by `extend_from_slice`; the verified
/// contract preserves the inherited prefix, appends exactly the child length,
/// and relates each appended element to its child source by the standard
/// `cloned` relation.
pub fn append_vec<T: Clone>(out: &mut Vec<T>, child: &[T])
    ensures
        final(out)@.len() == old(out)@.len() + child@.len(),
        forall|i: int|
            0 <= i < old(out)@.len() ==> final(out)@[i] == old(out)@[i],
        forall|i: int|
            0 <= i < child@.len() ==>
                cloned::<T>(child@[i], final(out)@[old(out)@.len() + i]),
{
    out.extend_from_slice(child);
}


/// Abstract model of the append/union fields in `Scope::merge`.  Concrete
/// runtime values are represented by opaque IDs; the model fixes the order,
/// child-wins map behavior and append semantics that the parser/merge must
/// follow.
pub struct ContainerModel {
    pub error_documents: Seq<(u16, u64)>,
    pub aliases: Seq<u64>,
    pub redirects: Seq<u64>,
    pub handlers: Seq<u64>,
    pub unsupported_filters: Seq<u64>,
    pub add_types: Seq<u64>,
    pub remove_types: Seq<u64>,
    pub set_headers: Seq<u64>,
    pub add_headers: Seq<u64>,
    pub unset_headers: Seq<u64>,
    pub set_env: Seq<u64>,
    pub unset_env: Seq<u64>,
    pub pass_env: Seq<u64>,
    pub set_env_if: Seq<u64>,
    pub cookies: Seq<u64>,
    pub vary: Seq<u64>,
    pub rewrite_rules: Seq<u64>,
    pub compression_rules: Seq<u64>,
    pub proxy_rules: Seq<u64>,
    pub proxy_passes: Seq<u64>,
    pub proxy_reverses: Seq<u64>,
    pub rewrite_maps: Seq<(u64, u64)>,
}

pub open spec fn merge_containers(
    parent: ContainerModel,
    child: ContainerModel,
) -> ContainerModel {
    ContainerModel {
        error_documents: parent.error_documents + child.error_documents,
        aliases: parent.aliases + child.aliases,
        redirects: parent.redirects + child.redirects,
        handlers: parent.handlers + child.handlers,
        unsupported_filters: parent.unsupported_filters + child.unsupported_filters,
        add_types: parent.add_types + child.add_types,
        remove_types: parent.remove_types + child.remove_types,
        set_headers: parent.set_headers + child.set_headers,
        add_headers: parent.add_headers + child.add_headers,
        unset_headers: parent.unset_headers + child.unset_headers,
        set_env: parent.set_env + child.set_env,
        unset_env: parent.unset_env + child.unset_env,
        pass_env: parent.pass_env + child.pass_env,
        set_env_if: parent.set_env_if + child.set_env_if,
        cookies: parent.cookies + child.cookies,
        vary: parent.vary + child.vary,
        rewrite_rules: parent.rewrite_rules + child.rewrite_rules,
        compression_rules: parent.compression_rules + child.compression_rules,
        proxy_rules: parent.proxy_rules + child.proxy_rules,
        proxy_passes: parent.proxy_passes + child.proxy_passes,
        proxy_reverses: parent.proxy_reverses + child.proxy_reverses,
        rewrite_maps: parent.rewrite_maps + child.rewrite_maps,
    }
}

/// Appending a child container never reorders or drops the parent prefix.
pub proof fn container_append_preserves_parent(
    parent: Seq<u64>,
    child: Seq<u64>,
)
    ensures
        (parent + child).subrange(0, parent.len() as int) == parent,
        (parent + child).len() == parent.len() + child.len(),
{
}

/// Child entries are appended after the parent prefix, so a reverse lookup
/// observes the child value first.  This is the list-backed replacement for
/// map insertion order in `Scope::merge`.
pub open spec fn container_lookup_pair<K, V>(
    pairs: Seq<(K, V)>,
    key: K,
) -> Option<V>
    decreases pairs.len(),
{
    if pairs.len() == 0 {
        None
    } else if pairs[pairs.len() - 1].0 == key {
        Some(pairs[pairs.len() - 1].1)
    } else {
        container_lookup_pair(pairs.drop_last(), key)
    }
}

pub proof fn container_append_child_lookup_wins<K, V>(
    parent: Seq<(K, V)>,
    child: Seq<(K, V)>,
    key: K,
)
    ensures
        child.len() > 0 && child[child.len() - 1].0 == key
            ==> container_lookup_pair(parent + child, key)
                == Some(child[child.len() - 1].1),
{
}


// ---------------------------------------------------------------------------
// HTTP/2 request admission and stream-budget model
// ---------------------------------------------------------------------------

/// The admission result for one HTTP/2 request head.  The order of the
/// constructors is the rejection precedence used by the adapter: a malformed
/// method is rejected before target/header limits are reported.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H2HeadDecision {
    Accept,
    InvalidMethod,
    TargetTooLong,
    TooManyHeaders,
    HeaderFieldTooLarge,
}

/// The method predicate used by the HTTP/2 adapter: RFC 9110 token, no
/// empty method, and the same 64-byte ceiling as the HTTP/1 parser.
pub open spec fn h2_method_ok_spec(method: Seq<u8>) -> bool {
    method.len() > 0 && method.len() <= 64 && all_tchars(method)
}

pub fn h2_method_ok(method: &[u8]) -> (ok: bool)
    ensures ok == h2_method_ok_spec(method@),
{
    if method.len() == 0 || method.len() > 64 {
        false
    } else {
        valid_token(method)
    }
}

/// Decide one complete HTTP/2 head without parsing it twice.
///
/// The caller supplies the method bytes and the largest `name + value` field
/// size.  The postcondition is deliberately useful on every branch: an
/// `Accept` establishes all four bounds, while each rejection constructor
/// establishes exactly which bound failed after all earlier checks passed.
/// This gives the adapter one decision point instead of an open-coded `if`
/// ladder that can drift from the HTTP/1 parser.
pub fn h2_head_admit(
    method: &[u8],
    target_len: u64,
    target_limit: u64,
    header_count: u64,
    header_limit: u64,
    largest_field: u64,
    field_limit: u64,
) -> (decision: H2HeadDecision)
    ensures
        decision == H2HeadDecision::Accept ==> {
            &&& h2_method_ok_spec(method@)
            &&& target_len <= target_limit
            &&& header_count <= header_limit
            &&& largest_field <= field_limit
        },
        decision == H2HeadDecision::InvalidMethod ==> !h2_method_ok_spec(method@),
        decision == H2HeadDecision::TargetTooLong ==> {
            &&& h2_method_ok_spec(method@)
            &&& target_len > target_limit
        },
        decision == H2HeadDecision::TooManyHeaders ==> {
            &&& h2_method_ok_spec(method@)
            &&& target_len <= target_limit
            &&& header_count > header_limit
        },
        decision == H2HeadDecision::HeaderFieldTooLarge ==> {
            &&& h2_method_ok_spec(method@)
            &&& target_len <= target_limit
            &&& header_count <= header_limit
            &&& largest_field > field_limit
        },
{
    let method_ok = h2_method_ok(method);
    if !method_ok {
        H2HeadDecision::InvalidMethod
    } else if target_len > target_limit {
        H2HeadDecision::TargetTooLong
    } else if header_count > header_limit {
        H2HeadDecision::TooManyHeaders
    } else if largest_field > field_limit {
        H2HeadDecision::HeaderFieldTooLarge
    } else {
        H2HeadDecision::Accept
    }
}

/// A request body may be appended only when it stays within the configured
/// limit.  The subtraction is guarded, so a malicious length cannot wrap.
pub fn h2_body_admit(current: u64, add: u64, limit: u64) -> (ok: bool)
    ensures ok == (current <= limit && add <= limit - current)
{
    if current > limit {
        false
    } else {
        add <= limit - current
    }
}

/// Monotone body-budget state.  The adapter advances this alongside the
/// concrete `Vec`; keeping the length as an explicit model prevents a future
/// refactor from accidentally resetting or bypassing the limit check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct H2BodyState {
    pub len: u64,
    pub limit: u64,
}

pub open spec fn h2_body_inv(s: H2BodyState) -> bool {
    s.len <= s.limit
}

pub fn h2_body_init(limit: u64) -> (s: H2BodyState)
    ensures h2_body_inv(s), s.len == 0, s.limit == limit,
{
    H2BodyState { len: 0, limit }
}

pub fn h2_body_append(state: H2BodyState, add: u64) -> (out: Option<H2BodyState>)
    requires h2_body_inv(state),
    ensures
        match out {
            Some(next) => {
                &&& h2_body_inv(next)
                &&& next.limit == state.limit
                &&& next.len == state.len + add
                &&& add <= state.limit - state.len
            }
            None => add > state.limit - state.len,
        },
{
    if add > state.limit - state.len {
        None
    } else {
        Some(H2BodyState { len: state.len + add, limit: state.limit })
    }
}

/// Total decoded header-list budget.  The h2 crate also enforces its
/// `max_header_list_size`; this is the adapter-level check used before a
/// request head is converted into the shared HTTP request.
/// Monotone decoded-header-list budget.  The h2 crate's HPACK limit is the
/// wire-side control; this model is the adapter's explicit total-header
/// state, used while converting the decoded list into the shared request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct H2HeaderState {
    pub total: u64,
    pub limit: u64,
}

pub open spec fn h2_header_inv(s: H2HeaderState) -> bool {
    s.total <= s.limit
}

pub fn h2_header_init(limit: u64) -> (s: H2HeaderState)
    ensures h2_header_inv(s), s.total == 0, s.limit == limit,
{
    H2HeaderState { total: 0, limit }
}

pub fn h2_header_add(state: H2HeaderState, add: u64) -> (out: Option<H2HeaderState>)
    requires h2_header_inv(state),
    ensures
        match out {
            Some(next) => {
                &&& h2_header_inv(next)
                &&& next.limit == state.limit
                &&& next.total == state.total + add
                &&& add <= state.limit - state.total
            }
            None => add > state.limit - state.total,
        },
{
    if add > state.limit - state.total {
        None
    } else {
        Some(H2HeaderState { total: state.total + add, ..state })
    }
}

pub fn h2_header_total_admit(total: u64, limit: u64) -> (ok: bool)
    ensures ok == (total <= limit),
{
    total <= limit
}

pub fn h2_target_admit(len: u64, limit: u64) -> (ok: bool)
    ensures ok == (len <= limit)
{
    len <= limit
}

/// Header count and one field size are both bounded independently.
pub fn h2_header_admit(
    count: u64,
    field_size: u64,
    max_count: u64,
    max_field: u64,
) -> (ok: bool)
    ensures ok == (count <= max_count && field_size <= max_field)
{
    count <= max_count && field_size <= max_field
}

/// Abstract per-connection H2 stream/reset budget.  The h2 crate owns the
/// wire state machine; this model states the bound the adapter expects from a
/// conforming projection: active streams and pending resets never exceed the
/// configured maxima, and every transition is total (it returns `None` rather
/// than underflowing).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct H2Budget {
    pub active: u64,
    pub max_active: u64,
    pub pending_resets: u64,
    pub max_pending_resets: u64,
}

pub open spec fn h2_budget_inv(b: H2Budget) -> bool {
    b.active <= b.max_active && b.pending_resets <= b.max_pending_resets
}

pub fn h2_budget_new(max_active: u64, max_pending_resets: u64) -> (b: H2Budget)
    ensures
        h2_budget_inv(b),
        b.active == 0,
        b.pending_resets == 0,
        b.max_active == max_active,
        b.max_pending_resets == max_pending_resets,
{
    H2Budget {
        active: 0,
        max_active,
        pending_resets: 0,
        max_pending_resets,
    }
}

pub fn h2_budget_begin(b: H2Budget) -> (out: Option<H2Budget>)
    requires h2_budget_inv(b),
    ensures
        match out {
            Some(next) => {
                &&& h2_budget_inv(next)
                &&& next.active == b.active + 1
                &&& next.pending_resets == b.pending_resets
                &&& next.max_active == b.max_active
                &&& next.max_pending_resets == b.max_pending_resets
                &&& b.active < b.max_active
            }
            None => b.active >= b.max_active,
        },
{
    if b.active >= b.max_active {
        None
    } else {
        Some(H2Budget { active: b.active + 1, ..b })
    }
}

pub fn h2_budget_finish(b: H2Budget) -> (out: Option<H2Budget>)
    requires h2_budget_inv(b),
    ensures
        match out {
            Some(next) => {
                &&& h2_budget_inv(next)
                &&& next.active == b.active - 1
                &&& next.pending_resets == b.pending_resets
                &&& next.max_active == b.max_active
                &&& next.max_pending_resets == b.max_pending_resets
                &&& b.active > 0
            }
            None => b.active == 0,
        },
{
    if b.active == 0 {
        None
    } else {
        Some(H2Budget { active: b.active - 1, ..b })
    }
}

pub fn h2_budget_reset(b: H2Budget) -> (out: Option<H2Budget>)
    requires h2_budget_inv(b),
    ensures
        match out {
            Some(next) => {
                &&& h2_budget_inv(next)
                &&& next.active == b.active
                &&& next.pending_resets == b.pending_resets + 1
                &&& next.max_active == b.max_active
                &&& next.max_pending_resets == b.max_pending_resets
                &&& b.pending_resets < b.max_pending_resets
            }
            None => b.pending_resets >= b.max_pending_resets,
        },
{
    if b.pending_resets >= b.max_pending_resets {
        None
    } else {
        Some(H2Budget { pending_resets: b.pending_resets + 1, ..b })
    }
}

pub fn h2_budget_reclaim(b: H2Budget) -> (out: Option<H2Budget>)
    requires h2_budget_inv(b),
    ensures
        match out {
            Some(next) => {
                &&& h2_budget_inv(next)
                &&& next.active == b.active
                &&& next.pending_resets == b.pending_resets - 1
                &&& next.max_active == b.max_active
                &&& next.max_pending_resets == b.max_pending_resets
                &&& b.pending_resets > 0
            }
            None => b.pending_resets == 0,
        },
{
    if b.pending_resets == 0 {
        None
    } else {
        Some(H2Budget { pending_resets: b.pending_resets - 1, ..b })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H2BudgetEvent {
    Begin,
    Finish,
    Reset,
    Reclaim,
}

pub open spec fn h2_budget_step_spec(
    b: H2Budget,
    event: H2BudgetEvent,
) -> Option<H2Budget> {
    match event {
        H2BudgetEvent::Begin => if b.active >= b.max_active {
            None
        } else {
            Some(H2Budget {
                active: (b.active + 1) as u64,
                max_active: b.max_active,
                pending_resets: b.pending_resets,
                max_pending_resets: b.max_pending_resets,
            })
        },
        H2BudgetEvent::Finish => if b.active == 0 {
            None
        } else {
            Some(H2Budget {
                active: (b.active - 1) as u64,
                max_active: b.max_active,
                pending_resets: b.pending_resets,
                max_pending_resets: b.max_pending_resets,
            })
        },
        H2BudgetEvent::Reset => if b.pending_resets >= b.max_pending_resets {
            None
        } else {
            Some(H2Budget {
                active: b.active,
                max_active: b.max_active,
                pending_resets: (b.pending_resets + 1) as u64,
                max_pending_resets: b.max_pending_resets,
            })
        },
        H2BudgetEvent::Reclaim => if b.pending_resets == 0 {
            None
        } else {
            Some(H2Budget {
                active: b.active,
                max_active: b.max_active,
                pending_resets: (b.pending_resets - 1) as u64,
                max_pending_resets: b.max_pending_resets,
            })
        },
    }
}

/// Bound settings used by the HTTP/2 adapter.  The values are deliberately
/// small and are consumed by the h2 builder; they are also the reference
/// limits for the adapter-level flow/header models.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct H2Settings {
    pub max_concurrent_streams: u32,
    pub max_header_list: u32,
    pub initial_window: u32,
    pub initial_connection_window: u32,
    pub max_frame: u32,
    pub max_reset_streams: u32,
    pub max_send_buffer: u32,
}

pub open spec fn h2_settings_sane(s: H2Settings) -> bool {
    &&& s.max_concurrent_streams > 0 && s.max_concurrent_streams <= 1024
    &&& s.max_header_list > 0 && s.max_header_list <= 16 * 1024 * 1024
    &&& s.initial_window > 0 && s.initial_window <= 16 * 1024 * 1024
    &&& s.initial_connection_window >= s.initial_window
    &&& s.initial_connection_window <= 16 * 1024 * 1024
    &&& s.max_frame >= 16 * 1024 && s.max_frame <= 16 * 1024 * 1024
    &&& s.max_reset_streams > 0 && s.max_reset_streams <= 1024
    &&& s.max_send_buffer > 0 && s.max_send_buffer <= 16 * 1024 * 1024
}

pub fn h2_settings() -> (s: H2Settings)
    ensures h2_settings_sane(s),
{
    H2Settings {
        max_concurrent_streams: 100,
        max_header_list: 131_072,
        initial_window: 256 * 1024,
        initial_connection_window: 1024 * 1024,
        max_frame: 16 * 1024,
        max_reset_streams: 100,
        max_send_buffer: 1024 * 1024,
    }
}

/// Abstract HTTP/2 flow-control state.  The h2 crate owns the wire windows;
/// this model records the bound the adapter/config contract expects:
/// connection and stream windows stay within their maxima, and the send
/// buffer never exceeds its configured cap.  The `charge`, `credit` and
/// `enqueue` transitions are total and reject underflow/overrun.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct H2Flow {
    pub conn_window: u64,
    pub stream_window: u64,
    pub pending_send: u64,
    pub max_conn_window: u64,
    pub max_stream_window: u64,
    pub max_send: u64,
}

pub open spec fn h2_flow_inv(f: H2Flow) -> bool {
    &&& f.conn_window <= f.max_conn_window
    &&& f.stream_window <= f.max_stream_window
    &&& f.pending_send <= f.max_send
}

pub fn h2_flow_new(
    initial_conn_window: u64,
    initial_stream_window: u64,
    max_send: u64,
) -> (f: H2Flow)
    ensures
        h2_flow_inv(f),
        f.conn_window == initial_conn_window,
        f.stream_window == initial_stream_window,
        f.pending_send == 0,
        f.max_conn_window == initial_conn_window,
        f.max_stream_window == initial_stream_window,
        f.max_send == max_send,
{
    H2Flow {
        conn_window: initial_conn_window,
        stream_window: initial_stream_window,
        pending_send: 0,
        max_conn_window: initial_conn_window,
        max_stream_window: initial_stream_window,
        max_send,
    }
}

pub fn h2_flow_charge(f: H2Flow, amount: u64) -> (out: Option<H2Flow>)
    requires h2_flow_inv(f),
    ensures
        match out {
            Some(next) => {
                &&& h2_flow_inv(next)
                &&& next.conn_window == f.conn_window - amount
                &&& next.stream_window == f.stream_window - amount
                &&& next.pending_send == f.pending_send
                &&& amount <= f.conn_window
                &&& amount <= f.stream_window
            }
            None => amount > f.conn_window || amount > f.stream_window,
        },
{
    if amount > f.conn_window || amount > f.stream_window {
        None
    } else {
        Some(H2Flow { conn_window: f.conn_window - amount, stream_window: f.stream_window - amount, ..f })
    }
}

pub fn h2_flow_credit(f: H2Flow, amount: u64) -> (out: H2Flow)
    requires h2_flow_inv(f),
    ensures
        h2_flow_inv(out),
        out.pending_send == f.pending_send,
        out.max_conn_window == f.max_conn_window,
        out.max_stream_window == f.max_stream_window,
        out.max_send == f.max_send,
        out.conn_window >= f.conn_window,
        out.stream_window >= f.stream_window,
        out.conn_window <= f.max_conn_window,
        out.stream_window <= f.max_stream_window,
{
    let conn_window = if amount > f.max_conn_window - f.conn_window {
        f.max_conn_window
    } else {
        f.conn_window + amount
    };
    let stream_window = if amount > f.max_stream_window - f.stream_window {
        f.max_stream_window
    } else {
        f.stream_window + amount
    };
    H2Flow {
        conn_window,
        stream_window,
        ..f
    }
}

pub fn h2_flow_enqueue(f: H2Flow, amount: u64) -> (out: Option<H2Flow>)
    requires h2_flow_inv(f),
    ensures
        match out {
            Some(next) => {
                &&& h2_flow_inv(next)
                &&& next.conn_window == f.conn_window
                &&& next.stream_window == f.stream_window
                &&& next.pending_send == f.pending_send + amount
                &&& amount <= f.max_send - f.pending_send
            }
            None => amount > f.max_send - f.pending_send,
        },
{
    if amount > f.max_send - f.pending_send {
        None
    } else {
        Some(H2Flow { pending_send: f.pending_send + amount, ..f })
    }
}

pub fn h2_flow_dequeue(f: H2Flow, amount: u64) -> (out: Option<H2Flow>)
    requires h2_flow_inv(f),
    ensures
        match out {
            Some(next) => {
                &&& h2_flow_inv(next)
                &&& next.conn_window == f.conn_window
                &&& next.stream_window == f.stream_window
                &&& next.pending_send == f.pending_send - amount
                &&& amount <= f.pending_send
            }
            None => amount > f.pending_send,
        },
{
    if amount > f.pending_send {
        None
    } else {
        Some(H2Flow { pending_send: f.pending_send - amount, ..f })
    }
}

/// Idempotent cleanup registration, mirroring mod_http2's `add_for_purge`.
/// A stream may be scheduled for destruction by both an early RST callback and
/// a close callback; the second registration must be a no-op or the same
/// object is destroyed twice.  Vapache has no C spurge array, but its adapter
/// uses the same identity rule for task completion/reset events.
pub open spec fn h2_purge_contains(ids: Seq<u64>, id: u64) -> bool {
    exists|i: int| 0 <= i < ids.len() && ids[i] == id
}

pub open spec fn h2_purge_add(ids: Seq<u64>, id: u64) -> Seq<u64> {
    if h2_purge_contains(ids, id) {
        ids
    } else {
        ids.push(id)
    }
}

pub proof fn h2_purge_add_idempotent(ids: Seq<u64>, id: u64)
    ensures h2_purge_add(h2_purge_add(ids, id), id) == h2_purge_add(ids, id),
{
    if h2_purge_contains(ids, id) {
    } else {
        assert(ids.push(id)[ids.len() as int] == id);
        assert(h2_purge_contains(ids.push(id), id));
    }
}

/// Runtime membership check for the same cleanup set.
pub fn h2_purge_contains_exec(ids: &[u64], id: u64) -> (found: bool)
    ensures found == h2_purge_contains(ids@, id),
{
    let mut i: usize = 0;
    while i < ids.len()
        invariant
            0 <= i <= ids.len(),
            forall|j: int| 0 <= j < i ==> ids@[j] != id,
        decreases ids.len() - i,
    {
        if ids[i] == id {
            return true;
        }
        i = i + 1;
    }
    assert forall|j: int| 0 <= j < ids@.len() ==> ids@[j] != id by {
    }
    false
}

/// Invariant for the adapter-side stream table: active and pending-reset
/// stream IDs are each unique and the two sets are disjoint.  This is the
/// state the `H2StreamIds` ledger maintains around the verified admission
/// step; the h2 crate owns wire-level frame ordering and the HTTP/2 state
/// machine itself.
pub open spec fn h2_stream_table_inv(active: Seq<u64>, pending: Seq<u64>) -> bool {
    &&& active.no_duplicates()
    &&& pending.no_duplicates()
    &&& forall|i: int, j: int|
        0 <= i < active.len() && 0 <= j < pending.len() ==> active[i] != pending[j]
}

/// A stream may begin only if its ID is neither currently active nor awaiting
/// reset cleanup.  This is the combined admission check used by the runtime;
/// it prevents a duplicate early-RST/completion path from creating two
/// logical streams with the same ID.
pub fn h2_stream_admit(active: &[u64], pending: &[u64], id: u64) -> (ok: bool)
    ensures ok == (!active@.contains(id) && !pending@.contains(id)),
{
    if h2_purge_contains_exec(active, id) {
        false
    } else if h2_purge_contains_exec(pending, id) {
        false
    } else {
        true
    }
}

/// Adapter-level stream lifecycle.  The h2 crate reports stream IDs and
/// resets; this model fixes the only legal local transitions so a closed
/// stream can never be reopened without a fresh admission (which the ID
/// ledger rejects).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H2StreamPhase {
    Idle,
    Active,
    AwaitingReset,
    Closed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H2StreamEvent {
    Begin,
    End,
    Reset,
    Reclaim,
}

pub open spec fn h2_stream_phase_step(
    phase: H2StreamPhase,
    event: H2StreamEvent,
) -> Option<H2StreamPhase> {
    match (phase, event) {
        (H2StreamPhase::Idle, H2StreamEvent::Begin) => Some(H2StreamPhase::Active),
        (H2StreamPhase::Active, H2StreamEvent::End) => Some(H2StreamPhase::AwaitingReset),
        (H2StreamPhase::Active, H2StreamEvent::Reset) => Some(H2StreamPhase::AwaitingReset),
        (H2StreamPhase::AwaitingReset, H2StreamEvent::End) => Some(H2StreamPhase::Closed),
        (H2StreamPhase::AwaitingReset, H2StreamEvent::Reclaim) => Some(H2StreamPhase::Closed),
        _ => None,
    }
}

/// Closed is absorbing: no event can move a closed stream back to Active or
/// AwaitingReset.  A fresh stream must be admitted through a new ID.
pub proof fn h2_closed_phase_is_absorbing(
    event: H2StreamEvent,
)
    ensures
        h2_stream_phase_step(H2StreamPhase::Closed, event).is_none(),
{
}

pub proof fn h2_stream_phase_preserves_no_reopen(
    phase: H2StreamPhase,
    event: H2StreamEvent,
)
    ensures
        h2_stream_phase_step(phase, event)
                == Some(H2StreamPhase::Active)
            ==> phase == H2StreamPhase::Idle && event == H2StreamEvent::Begin,
{
}

pub fn h2_budget_step(b: H2Budget, event: H2BudgetEvent) -> (out: Option<H2Budget>)
    requires h2_budget_inv(b),
    ensures
        out == h2_budget_step_spec(b, event),
        match out {
            Some(next) => h2_budget_inv(next),
            None => true,
        },
{
    match event {
        H2BudgetEvent::Begin => h2_budget_begin(b),
        H2BudgetEvent::Finish => h2_budget_finish(b),
        H2BudgetEvent::Reset => h2_budget_reset(b),
        H2BudgetEvent::Reclaim => h2_budget_reclaim(b),
    }
}

pub open spec fn h2_budget_replay(
    b: H2Budget,
    events: Seq<H2BudgetEvent>,
) -> Option<H2Budget>
    decreases events.len(),
{
    if events.len() == 0 {
        Some(b)
    } else {
        match h2_budget_step_spec(b, events[0]) {
            Some(next) => h2_budget_replay(next, events.skip(1)),
            None => None,
        }
    }
}

/// Any finite sequence of admitted/ended/reset/reclaimed transitions keeps
/// both counters within their configured maxima.  This is the induction
/// obligation behind the per-event postconditions above.
pub proof fn h2_budget_replay_preserves_inv(
    b: H2Budget,
    events: Seq<H2BudgetEvent>,
)
    requires h2_budget_inv(b),
    ensures
        match h2_budget_replay(b, events) {
            Some(next) => h2_budget_inv(next),
            None => true,
        },
    decreases events.len(),
{
    if events.len() == 0 {
    } else {
        let event = events[0];
        match event {
            H2BudgetEvent::Begin => {
                if b.active >= b.max_active {
                    assert(h2_budget_step_spec(b, event) == None);
                } else {
                    let next = H2Budget {
                        active: (b.active + 1) as u64,
                        max_active: b.max_active,
                        pending_resets: b.pending_resets,
                        max_pending_resets: b.max_pending_resets,
                    };
                    assert(h2_budget_step_spec(b, event) == Some(next));
                    assert(h2_budget_inv(next));
                    h2_budget_replay_preserves_inv(next, events.skip(1));
                }
            }
            H2BudgetEvent::Finish => {
                if b.active == 0 {
                    assert(h2_budget_step_spec(b, event) == None);
                } else {
                    let next = H2Budget {
                        active: (b.active - 1) as u64,
                        max_active: b.max_active,
                        pending_resets: b.pending_resets,
                        max_pending_resets: b.max_pending_resets,
                    };
                    assert(h2_budget_step_spec(b, event) == Some(next));
                    assert(h2_budget_inv(next));
                    h2_budget_replay_preserves_inv(next, events.skip(1));
                }
            }
            H2BudgetEvent::Reset => {
                if b.pending_resets >= b.max_pending_resets {
                    assert(h2_budget_step_spec(b, event) == None);
                } else {
                    let next = H2Budget {
                        active: b.active,
                        max_active: b.max_active,
                        pending_resets: (b.pending_resets + 1) as u64,
                        max_pending_resets: b.max_pending_resets,
                    };
                    assert(h2_budget_step_spec(b, event) == Some(next));
                    assert(h2_budget_inv(next));
                    h2_budget_replay_preserves_inv(next, events.skip(1));
                }
            }
            H2BudgetEvent::Reclaim => {
                if b.pending_resets == 0 {
                    assert(h2_budget_step_spec(b, event) == None);
                } else {
                    let next = H2Budget {
                        active: b.active,
                        max_active: b.max_active,
                        pending_resets: (b.pending_resets - 1) as u64,
                        max_pending_resets: b.max_pending_resets,
                    };
                    assert(h2_budget_step_spec(b, event) == Some(next));
                    assert(h2_budget_inv(next));
                    h2_budget_replay_preserves_inv(next, events.skip(1));
                }
            }
        }
    }
}

} // verus!
