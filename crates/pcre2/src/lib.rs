//! A memory-safe, non-backtracking PCRE2 compatibility layer for vapache.
//!
//! This crate intentionally mirrors the useful part of the `pcre2::bytes`
//! API.  It compiles the regular subset of the PCRE2 10.46 pattern language
//! to Rust's bounded automata engine.  Constructs that require a recursive
//! backtracking interpreter (backreferences, recursion, look-around,
//! conditionals and backtracking verbs) are rejected at compile time.
//!
//! The matcher is byte oriented by default, just like PCRE2's 8-bit API
//! without `PCRE2_UTF`/`PCRE2_UCP`.  No executable memory or native code is
//! used.  Pattern, subject, capture and pattern×subject work ceilings are
//! checked through the verified vapache resource kernel.

use std::collections::HashMap;
use std::fmt;
use std::ops::Index;
use std::sync::Arc;

const DEFAULT_PATTERN_LIMIT: usize = 64 * 1024;
const DEFAULT_SUBJECT_LIMIT: usize = 64 * 1024;
const DEFAULT_WORK_LIMIT: u64 = 16 * 1024 * 1024;
const DEFAULT_CAPTURE_LIMIT: usize = 128;
const DEFAULT_SIZE_LIMIT: usize = 2 * 1024 * 1024;
const DEFAULT_NEST_LIMIT: u32 = 64;
const KEEP_PREFIX: &str = "__vapache_pcre2_keep_";

/// Error category.  Unsupported syntax is distinct from malformed syntax so
/// callers can report a deliberate fail-closed compatibility decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Syntax,
    Unsupported,
    ResourceLimit,
}

/// A PCRE2-compatible compile or match error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    offset: Option<usize>,
}

impl Error {
    fn syntax(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Syntax,
            message: message.into(),
            offset: None,
        }
    }

    fn syntax_at(offset: usize, message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Syntax,
            message: message.into(),
            offset: Some(offset),
        }
    }

    fn unsupported(offset: usize, construct: &str) -> Self {
        Self {
            kind: ErrorKind::Unsupported,
            message: format!("{construct} requires PCRE2 backtracking semantics"),
            offset: Some(offset),
        }
    }

    fn resource(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::ResourceLimit,
            message: message.into(),
            offset: None,
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn offset(&self) -> Option<usize> {
        self.offset
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(offset) = self.offset {
            write!(f, "{} at pattern offset {offset}", self.message)
        } else {
            f.write_str(&self.message)
        }
    }
}

impl std::error::Error for Error {}

pub mod bytes {
    use super::*;

    /// A byte range in a matched subject.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Match<'s> {
        subject: &'s [u8],
        start: usize,
        end: usize,
    }

    impl<'s> Match<'s> {
        pub fn start(&self) -> usize {
            self.start
        }

        pub fn end(&self) -> usize {
            self.end
        }

        pub fn as_bytes(&self) -> &'s [u8] {
            &self.subject[self.start..self.end]
        }
    }

    #[derive(Clone, Debug)]
    struct Config {
        caseless: bool,
        dotall: bool,
        extended: bool,
        multi_line: bool,
        crlf: bool,
        ucp: bool,
        utf: bool,
        backtracking: bool,
        pattern_limit: usize,
        subject_limit: usize,
        work_limit: u64,
        capture_limit: usize,
        size_limit: usize,
        nest_limit: u32,
    }

    impl Default for Config {
        fn default() -> Self {
            Self {
                caseless: false,
                dotall: false,
                extended: false,
                multi_line: false,
                crlf: false,
                ucp: false,
                utf: false,
                backtracking: false,
                pattern_limit: DEFAULT_PATTERN_LIMIT,
                subject_limit: DEFAULT_SUBJECT_LIMIT,
                work_limit: DEFAULT_WORK_LIMIT,
                capture_limit: DEFAULT_CAPTURE_LIMIT,
                size_limit: DEFAULT_SIZE_LIMIT,
                nest_limit: DEFAULT_NEST_LIMIT,
            }
        }
    }

    /// Builder corresponding to `pcre2::bytes::RegexBuilder`.
    #[derive(Clone, Debug, Default)]
    pub struct RegexBuilder {
        config: Config,
    }

    impl RegexBuilder {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn build(&self, pattern: &str) -> Result<Regex, Error> {
            if !vapache_verified::regex_engine_mode_admit(self.config.backtracking, false) {
                return Err(Error::resource(
                    "the backtracking compatibility engine is not available",
                ));
            }
            if !vapache_verified::regex_compile_resource_admit(
                pattern.len() as u64,
                self.config.pattern_limit as u64,
            ) {
                return Err(Error::resource("pattern exceeds the configured byte limit"));
            }

            let translation = translate(
                pattern,
                self.config.multi_line,
                self.config.crlf,
                self.config.extended,
            )?;
            if translation.pattern.len() > self.config.pattern_limit.saturating_mul(4) {
                return Err(Error::resource(
                    "translated pattern exceeds the expansion limit",
                ));
            }

            let mut builder = regex::bytes::RegexBuilder::new(&translation.pattern);
            builder
                .case_insensitive(self.config.caseless)
                .dot_matches_new_line(self.config.dotall)
                .ignore_whitespace(self.config.extended)
                .multi_line(self.config.multi_line)
                .crlf(self.config.crlf)
                .unicode(self.config.ucp || self.config.utf)
                .size_limit(self.config.size_limit)
                .nest_limit(self.config.nest_limit);
            let inner = builder
                .build()
                .map_err(|error| Error::syntax(error.to_string()))?;

            let inner_names: Vec<Option<String>> = inner
                .capture_names()
                .map(|name| name.map(ToOwned::to_owned))
                .collect();
            let mut public_to_inner = vec![0];
            let mut keep_groups = Vec::new();
            let mut capture_names = vec![None];
            let mut capture_names_idx = HashMap::new();
            for (index, name) in inner_names.iter().enumerate().skip(1) {
                if name
                    .as_deref()
                    .is_some_and(|name| name.starts_with(KEEP_PREFIX))
                {
                    keep_groups.push(index);
                    continue;
                }
                let public = public_to_inner.len();
                public_to_inner.push(index);
                capture_names.push(name.clone());
                if let Some(name) = name {
                    capture_names_idx.insert(name.clone(), public);
                }
            }
            if public_to_inner.len() > self.config.capture_limit {
                return Err(Error::resource(
                    "capture count exceeds the configured limit",
                ));
            }
            if !vapache_verified::regex_capture_resource_admit(
                public_to_inner.len() as u64,
                self.config.capture_limit as u64,
            ) {
                return Err(Error::resource("capture count exceeds the verified limit"));
            }

            Ok(Regex {
                config: Arc::new(self.config.clone()),
                pattern: pattern.to_owned(),
                translated_pattern: translation.pattern,
                complexity: translation.complexity.max(1),
                final_newline_fallback: translation.final_newline_fallback,
                inner,
                public_to_inner: Arc::new(public_to_inner),
                keep_groups: Arc::new(keep_groups),
                capture_names: Arc::new(capture_names),
                capture_names_idx: Arc::new(capture_names_idx),
            })
        }

        pub fn caseless(&mut self, yes: bool) -> &mut Self {
            self.config.caseless = yes;
            self
        }

        pub fn dotall(&mut self, yes: bool) -> &mut Self {
            self.config.dotall = yes;
            self
        }

        pub fn extended(&mut self, yes: bool) -> &mut Self {
            self.config.extended = yes;
            self
        }

        pub fn multi_line(&mut self, yes: bool) -> &mut Self {
            self.config.multi_line = yes;
            self
        }

        pub fn crlf(&mut self, yes: bool) -> &mut Self {
            self.config.crlf = yes;
            self
        }

        pub fn ucp(&mut self, yes: bool) -> &mut Self {
            self.config.ucp = yes;
            self
        }

        pub fn utf(&mut self, yes: bool) -> &mut Self {
            self.config.utf = yes;
            self
        }

        #[deprecated(note = "invalid UTF subjects are handled without undefined behavior")]
        pub fn disable_utf_check(&mut self) -> &mut Self {
            self
        }

        /// Accepted for source compatibility. The Rust automata are always
        /// compiled ahead of use and never allocate executable memory.
        pub fn jit(&mut self, _yes: bool) -> &mut Self {
            self
        }

        /// Accepted for source compatibility; see [`Self::jit`].
        pub fn jit_if_available(&mut self, _yes: bool) -> &mut Self {
            self
        }

        /// Accepted for source compatibility. There is no native JIT stack.
        pub fn max_jit_stack_size(&mut self, _bytes: Option<usize>) -> &mut Self {
            self
        }

        /// Backtracking is disabled by default. Enabling it fails compilation
        /// because vapache deliberately ships no recursive fallback engine.
        pub fn backtracking(&mut self, yes: bool) -> &mut Self {
            self.config.backtracking = yes;
            self
        }

        pub fn max_pattern_size(&mut self, bytes: usize) -> &mut Self {
            self.config.pattern_limit = bytes;
            self
        }

        pub fn max_subject_size(&mut self, bytes: usize) -> &mut Self {
            self.config.subject_limit = bytes;
            self
        }

        pub fn match_limit(&mut self, work: u64) -> &mut Self {
            self.config.work_limit = work;
            self
        }

        pub fn capture_limit(&mut self, captures: usize) -> &mut Self {
            self.config.capture_limit = captures;
            self
        }

        pub fn size_limit(&mut self, bytes: usize) -> &mut Self {
            self.config.size_limit = bytes;
            self
        }

        pub fn nest_limit(&mut self, depth: u32) -> &mut Self {
            self.config.nest_limit = depth;
            self
        }
    }

    /// A compiled, shareable regular expression.
    #[derive(Clone)]
    pub struct Regex {
        config: Arc<Config>,
        pattern: String,
        translated_pattern: String,
        complexity: usize,
        final_newline_fallback: bool,
        inner: regex::bytes::Regex,
        public_to_inner: Arc<Vec<usize>>,
        keep_groups: Arc<Vec<usize>>,
        capture_names: Arc<Vec<Option<String>>>,
        capture_names_idx: Arc<HashMap<String, usize>>,
    }

    impl fmt::Debug for Regex {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("Regex").field(&self.pattern).finish()
        }
    }

    impl Regex {
        pub fn new(pattern: &str) -> Result<Self, Error> {
            RegexBuilder::new().build(pattern)
        }

        fn check_subject(&self, subject_len: usize, start: usize) -> Result<(), Error> {
            assert!(start <= subject_len, "start must be <= subject.len()");
            if !vapache_verified::regex_match_resource_admit(
                self.complexity as u64,
                subject_len.saturating_sub(start) as u64,
                self.config.subject_limit as u64,
                self.config.work_limit,
            ) {
                return Err(Error::resource(
                    "subject or deterministic pattern×subject work exceeds the configured limit",
                ));
            }
            Ok(())
        }

        pub fn is_match(&self, subject: &[u8]) -> Result<bool, Error> {
            self.is_match_at(subject, 0)
        }

        pub fn is_match_at(&self, subject: &[u8], start: usize) -> Result<bool, Error> {
            Ok(self.capture_spans(subject, start)?.is_some())
        }

        pub fn find<'s>(&self, subject: &'s [u8]) -> Result<Option<Match<'s>>, Error> {
            self.find_at(subject, 0)
        }

        pub fn find_at<'s>(
            &self,
            subject: &'s [u8],
            start: usize,
        ) -> Result<Option<Match<'s>>, Error> {
            let Some(spans) = self.capture_spans(subject, start)? else {
                return Ok(None);
            };
            Ok(spans[0].map(|(start, end)| Match {
                subject,
                start,
                end,
            }))
        }

        pub fn captures<'s>(&self, subject: &'s [u8]) -> Result<Option<Captures<'s>>, Error> {
            self.captures_at(subject, 0)
        }

        fn captures_at<'s>(
            &self,
            subject: &'s [u8],
            start: usize,
        ) -> Result<Option<Captures<'s>>, Error> {
            Ok(self.capture_spans(subject, start)?.map(|spans| Captures {
                subject,
                spans,
                idx: Arc::clone(&self.capture_names_idx),
            }))
        }

        fn capture_spans(
            &self,
            subject: &[u8],
            start: usize,
        ) -> Result<Option<Vec<Option<(usize, usize)>>>, Error> {
            self.check_subject(subject.len(), start)?;
            let full = self.inner.captures_at(subject, start);
            let mut trimmed = None;
            if self.final_newline_fallback {
                let trim = if self.config.crlf && subject.ends_with(b"\r\n") {
                    2
                } else if subject.ends_with(b"\n") {
                    1
                } else {
                    0
                };
                if trim > 0 && start <= subject.len() - trim {
                    trimmed = self
                        .inner
                        .captures_at(&subject[..subject.len() - trim], start);
                }
            }
            // PCRE2 exposes both end-of-subject and pre-final-newline anchor
            // positions. Select the earlier leftmost match; if starts tie,
            // retain the full-subject result and its normal greedy priority.
            let captures = match (full, trimmed) {
                (Some(full), Some(trimmed)) => {
                    let full_start = full.get(0).expect("group zero matches").start();
                    let trimmed_start = trimmed.get(0).expect("group zero matches").start();
                    if trimmed_start < full_start {
                        Some(trimmed)
                    } else {
                        Some(full)
                    }
                }
                (full, trimmed) => full.or(trimmed),
            };
            let Some(captures) = captures else {
                return Ok(None);
            };
            let mut spans = Vec::with_capacity(self.public_to_inner.len());
            for &inner in self.public_to_inner.iter() {
                spans.push(
                    captures
                        .get(inner)
                        .map(|matched| (matched.start(), matched.end())),
                );
            }
            if let Some((_, end)) = spans[0] {
                let keep_start = self
                    .keep_groups
                    .iter()
                    .filter_map(|&group| captures.get(group).map(|matched| matched.start()))
                    .max();
                if let Some(keep_start) = keep_start {
                    spans[0] = Some((keep_start, end));
                }
            }
            Ok(Some(spans))
        }

        pub fn find_iter<'r, 's>(&'r self, subject: &'s [u8]) -> Matches<'r, 's> {
            Matches {
                re: self,
                subject,
                last_end: 0,
                last_match: None,
                done: false,
            }
        }

        pub fn captures_iter<'r, 's>(&'r self, subject: &'s [u8]) -> CaptureMatches<'r, 's> {
            CaptureMatches {
                re: self,
                subject,
                last_end: 0,
                last_match: None,
                done: false,
            }
        }

        pub fn captures_read<'s>(
            &self,
            locs: &mut CaptureLocations,
            subject: &'s [u8],
        ) -> Result<Option<Match<'s>>, Error> {
            self.captures_read_at(locs, subject, 0)
        }

        pub fn captures_read_at<'s>(
            &self,
            locs: &mut CaptureLocations,
            subject: &'s [u8],
            start: usize,
        ) -> Result<Option<Match<'s>>, Error> {
            if locs.spans.len() != self.captures_len() {
                return Err(Error::resource(
                    "capture locations belong to a different regex",
                ));
            }
            let Some(spans) = self.capture_spans(subject, start)? else {
                locs.spans.fill(None);
                return Ok(None);
            };
            locs.spans = spans;
            Ok(locs.spans[0].map(|(start, end)| Match {
                subject,
                start,
                end,
            }))
        }

        pub fn as_str(&self) -> &str {
            &self.pattern
        }

        /// The internal regular-language form, useful for audits and
        /// differential-test diagnostics.
        pub fn translated_pattern(&self) -> &str {
            &self.translated_pattern
        }

        pub fn capture_names(&self) -> &[Option<String>] {
            &self.capture_names
        }

        pub fn captures_len(&self) -> usize {
            self.public_to_inner.len()
        }

        pub fn capture_locations(&self) -> CaptureLocations {
            CaptureLocations {
                spans: vec![None; self.captures_len()],
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct CaptureLocations {
        spans: Vec<Option<(usize, usize)>>,
    }

    impl CaptureLocations {
        pub fn get(&self, i: usize) -> Option<(usize, usize)> {
            self.spans.get(i).copied().flatten()
        }

        pub fn len(&self) -> usize {
            self.spans.len()
        }

        pub fn is_empty(&self) -> bool {
            self.spans.is_empty()
        }
    }

    #[derive(Clone)]
    pub struct Captures<'s> {
        subject: &'s [u8],
        spans: Vec<Option<(usize, usize)>>,
        idx: Arc<HashMap<String, usize>>,
    }

    impl<'s> Captures<'s> {
        pub fn get(&self, i: usize) -> Option<Match<'s>> {
            self.spans
                .get(i)
                .copied()
                .flatten()
                .map(|(start, end)| Match {
                    subject: self.subject,
                    start,
                    end,
                })
        }

        pub fn name(&self, name: &str) -> Option<Match<'s>> {
            self.idx.get(name).and_then(|&index| self.get(index))
        }

        pub fn len(&self) -> usize {
            self.spans.len()
        }

        pub fn is_empty(&self) -> bool {
            self.spans.is_empty()
        }
    }

    impl fmt::Debug for Captures<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_list()
                .entries((0..self.len()).map(|index| self.get(index).map(|m| m.as_bytes())))
                .finish()
        }
    }

    impl Index<usize> for Captures<'_> {
        type Output = [u8];

        fn index(&self, index: usize) -> &Self::Output {
            self.get(index)
                .expect("capture group did not match")
                .as_bytes()
        }
    }

    impl Index<&str> for Captures<'_> {
        type Output = [u8];

        fn index(&self, name: &str) -> &Self::Output {
            self.name(name)
                .expect("capture group did not match")
                .as_bytes()
        }
    }

    pub struct Matches<'r, 's> {
        re: &'r Regex,
        subject: &'s [u8],
        last_end: usize,
        last_match: Option<usize>,
        done: bool,
    }

    impl<'r, 's> Iterator for Matches<'r, 's> {
        type Item = Result<Match<'s>, Error>;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                if self.done || self.last_end > self.subject.len() {
                    self.done = true;
                    return None;
                }
                match self.re.find_at(self.subject, self.last_end) {
                    Ok(Some(matched)) => {
                        if matched.start() == matched.end() {
                            self.last_end = matched.end() + 1;
                            // Match PCRE2's global-search rule: after a
                            // non-empty match, do not emit an empty match at
                            // the exact same ending position.
                            if self.last_match == Some(matched.end()) {
                                continue;
                            }
                        } else {
                            self.last_end = matched.end();
                        }
                        self.last_match = Some(matched.end());
                        return Some(Ok(matched));
                    }
                    Ok(None) => {
                        self.done = true;
                        return None;
                    }
                    Err(error) => {
                        self.done = true;
                        return Some(Err(error));
                    }
                }
            }
        }
    }

    pub struct CaptureMatches<'r, 's> {
        re: &'r Regex,
        subject: &'s [u8],
        last_end: usize,
        last_match: Option<usize>,
        done: bool,
    }

    impl<'r, 's> Iterator for CaptureMatches<'r, 's> {
        type Item = Result<Captures<'s>, Error>;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                if self.done || self.last_end > self.subject.len() {
                    self.done = true;
                    return None;
                }
                match self.re.captures_at(self.subject, self.last_end) {
                    Ok(Some(captures)) => {
                        let matched = captures.get(0).expect("group zero always matches");
                        if matched.start() == matched.end() {
                            self.last_end = matched.end() + 1;
                            if self.last_match == Some(matched.end()) {
                                continue;
                            }
                        } else {
                            self.last_end = matched.end();
                        }
                        self.last_match = Some(matched.end());
                        return Some(Ok(captures));
                    }
                    Ok(None) => {
                        self.done = true;
                        return None;
                    }
                    Err(error) => {
                        self.done = true;
                        return Some(Err(error));
                    }
                }
            }
        }
    }

    struct Translation {
        pattern: String,
        complexity: usize,
        final_newline_fallback: bool,
    }

    /// Translate PCRE-only regular constructs while rejecting every construct
    /// whose behavior depends on recursive backtracking.
    fn translate(
        pattern: &str,
        _multi_line: bool,
        _crlf: bool,
        extended: bool,
    ) -> Result<Translation, Error> {
        if let Some(offset) = invalid_quantifier_placement(pattern, extended) {
            return Err(Error::syntax_at(
                offset,
                "quantifier does not follow a repeatable item",
            ));
        }
        if let Some(offset) = ambiguous_nested_capture_repeat(pattern) {
            return Err(Error::unsupported(
                offset,
                "nested quantification with ambiguous capture history",
            ));
        }
        if pattern.contains("[:") && pattern.contains('-') {
            // PCRE2's range validation around POSIX classes differs from
            // Rust's class-set grammar. Reject the ambiguous combination
            // instead of accepting a pattern PCRE2 diagnoses as invalid.
            return Err(Error::unsupported(0, "POSIX class combined with a range"));
        }
        let bytes = pattern.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        let mut in_class = false;
        let mut keep_count = 0;
        let mut final_newline_fallback = false;
        while i < bytes.len() {
            if bytes[i] >= 0x80 {
                let ch = pattern[i..].chars().next().expect("valid UTF-8 pattern");
                out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
                i += ch.len_utf8();
                continue;
            }
            match bytes[i] {
                b'[' if !in_class => {
                    in_class = true;
                    out.push(b'[');
                    i += 1;
                }
                b'[' if in_class => {
                    if bytes.get(i + 1) == Some(&b':') {
                        if let Some(relative_end) =
                            bytes[i + 2..].windows(2).position(|pair| pair == b":]")
                        {
                            let name_end = i + 2 + relative_end;
                            let name = &pattern[i + 2..name_end];
                            if matches!(
                                name,
                                "alnum"
                                    | "alpha"
                                    | "ascii"
                                    | "blank"
                                    | "cntrl"
                                    | "digit"
                                    | "graph"
                                    | "lower"
                                    | "print"
                                    | "punct"
                                    | "space"
                                    | "upper"
                                    | "word"
                                    | "xdigit"
                            ) {
                                let end = name_end + 2;
                                out.extend_from_slice(&bytes[i..end]);
                                i = end;
                                continue;
                            }
                        }
                        out.extend_from_slice(b"\\x5B");
                    } else if matches!(bytes.get(i + 1), Some(b'.' | b'=')) {
                        return Err(Error::unsupported(i, "collating character class"));
                    } else {
                        // Rust classes allow nested set expressions; PCRE2
                        // treats an ordinary inner `[` as a member byte.
                        out.extend_from_slice(b"\\x5B");
                    }
                    i += 1;
                }
                b']' if in_class => {
                    in_class = false;
                    out.push(b']');
                    i += 1;
                }
                b'(' if !in_class && bytes.get(i + 1) == Some(&b'*') => {
                    return Err(Error::unsupported(i, "backtracking control verb"));
                }
                b'(' if !in_class && bytes.get(i + 1) == Some(&b'?') => {
                    if bytes.get(i + 2) == Some(&b'#') {
                        let Some(relative_end) = bytes[i + 3..].iter().position(|&b| b == b')')
                        else {
                            return Err(Error::syntax("unterminated PCRE comment group"));
                        };
                        i += 4 + relative_end;
                        continue;
                    }
                    match bytes.get(i + 2).copied() {
                        Some(b'=') | Some(b'!') | Some(b'>') | Some(b'(') | Some(b'|') => {
                            return Err(Error::unsupported(
                                i,
                                "assertion, atomic, conditional or branch-reset group",
                            ));
                        }
                        Some(b'<') if matches!(bytes.get(i + 3), Some(b'=') | Some(b'!')) => {
                            return Err(Error::unsupported(i, "look-behind assertion"));
                        }
                        Some(b'R') | Some(b'0'..=b'9') | Some(b'&') => {
                            return Err(Error::unsupported(i, "recursive subpattern"));
                        }
                        Some(b'P') if matches!(bytes.get(i + 3), Some(b'=') | Some(b'>')) => {
                            return Err(Error::unsupported(i, "named backreference or recursion"));
                        }
                        Some(b'\'') => {
                            let name_start = i + 3;
                            let Some(relative_end) =
                                bytes[name_start..].iter().position(|&b| b == b'\'')
                            else {
                                return Err(Error::syntax("unterminated named capture"));
                            };
                            let name_end = name_start + relative_end;
                            out.extend_from_slice(b"(?P<");
                            out.extend_from_slice(&bytes[name_start..name_end]);
                            out.push(b'>');
                            i = name_end + 1;
                        }
                        _ => {
                            out.push(b'(');
                            i += 1;
                        }
                    }
                }
                b'$' if !in_class => {
                    // Rust's `$` is strict in non-multiline mode. A retry on
                    // the subject without its final newline supplies PCRE2's
                    // default pre-final-newline position without introducing
                    // synthetic capture groups or consuming the newline.
                    out.push(b'$');
                    final_newline_fallback = true;
                    i += 1;
                }
                b'\\' => {
                    let Some(&escaped) = bytes.get(i + 1) else {
                        return Err(Error::syntax("trailing backslash"));
                    };
                    match escaped {
                        b'Q' => {
                            let start = i + 2;
                            let end = bytes[start..]
                                .windows(2)
                                .position(|pair| pair == b"\\E")
                                .map(|relative| start + relative)
                                .unwrap_or(bytes.len());
                            append_quoted_literal(&mut out, &pattern[start..end], extended);
                            i = if end < bytes.len() { end + 2 } else { end };
                        }
                        b'K' if !in_class => {
                            out.extend_from_slice(
                                format!("(?P<{KEEP_PREFIX}{keep_count}>)").as_bytes(),
                            );
                            keep_count += 1;
                            i += 2;
                        }
                        b'Z' if !in_class => {
                            out.extend_from_slice(b"(?-m:$)");
                            final_newline_fallback = true;
                            i += 2;
                        }
                        b'C' if !in_class => {
                            out.extend_from_slice(b"(?s:.)");
                            i += 2;
                        }
                        b'R' if !in_class => {
                            out.extend_from_slice(b"(?:\\r\\n|[\\n\\x0B\\f\\r\\x85])");
                            i += 2;
                        }
                        b'N' if !in_class => {
                            out.extend_from_slice(b"[^\\n]");
                            i += 2;
                        }
                        b'h' => {
                            if in_class {
                                out.extend_from_slice(b"\\x09\\x20\\xA0");
                            } else {
                                out.extend_from_slice(b"[\\x09\\x20\\xA0]");
                            }
                            i += 2;
                        }
                        b'v' => {
                            if in_class {
                                out.extend_from_slice(b"\\n\\x0B\\f\\r\\x85");
                            } else {
                                out.extend_from_slice(b"[\\n\\x0B\\f\\r\\x85]");
                            }
                            i += 2;
                        }
                        b'H' | b'V' => {
                            if in_class {
                                return Err(Error::unsupported(
                                    i,
                                    "complement class escape inside a class",
                                ));
                            }
                            if escaped == b'H' {
                                out.extend_from_slice(b"[^\\x09\\x20\\xA0]");
                            } else {
                                out.extend_from_slice(b"[^\\n\\x0B\\f\\r\\x85]");
                            }
                            i += 2;
                        }
                        b'a' => {
                            out.extend_from_slice(b"\\x07");
                            i += 2;
                        }
                        b'e' => {
                            out.extend_from_slice(b"\\x1B");
                            i += 2;
                        }
                        b'b' if in_class => {
                            out.extend_from_slice(b"\\x08");
                            i += 2;
                        }
                        b'c' => {
                            let Some(&control) = bytes.get(i + 2) else {
                                return Err(Error::syntax("incomplete control escape"));
                            };
                            if control >= 0x80 {
                                return Err(Error::syntax("control escape must be ASCII"));
                            }
                            // PCRE2 uppercases the ASCII byte and toggles bit
                            // 6. This intentionally differs from `& 0x1f`
                            // for punctuation (`\c:` is `z`).
                            let value = control.to_ascii_uppercase() ^ 0x40;
                            out.extend_from_slice(format!("\\x{value:02X}").as_bytes());
                            i += 3;
                        }
                        b'0' => {
                            let mut end = i + 2;
                            while end < bytes.len()
                                && end < i + 4
                                && matches!(bytes[end], b'0'..=b'7')
                            {
                                end += 1;
                            }
                            let value = u8::from_str_radix(&pattern[i + 1..end], 8)
                                .map_err(|_| Error::syntax("octal escape is outside byte range"))?;
                            out.extend_from_slice(format!("\\x{value:02X}").as_bytes());
                            i = end;
                        }
                        b'1'..=b'9' | b'g' | b'k' => {
                            return Err(Error::unsupported(i, "backreference"));
                        }
                        b'p' | b'P' | b'X' => {
                            return Err(Error::unsupported(
                                i,
                                "Unicode property or extended grapheme escape",
                            ));
                        }
                        _ => {
                            out.push(b'\\');
                            out.push(escaped);
                            i += 2;
                        }
                    }
                }
                b'+' if !in_class && matches!(out.last(), Some(b'*' | b'+' | b'?' | b'}')) => {
                    return Err(Error::unsupported(i, "possessive quantifier"));
                }
                b'{' if !in_class
                    && (bytes[i..].starts_with(b"{0}") || bytes[i..].starts_with(b"{0,0}")) =>
                {
                    // Rust's optimizer elides captures in an always-zero
                    // repetition, while PCRE2 retains their public slots.
                    return Err(Error::unsupported(i, "zero-count repetition"));
                }
                b'|' if !in_class
                    && (i == 0
                        || matches!(bytes.get(i.wrapping_sub(1)), Some(b'(' | b'|'))
                        || matches!(bytes.get(i + 1), None | Some(b')') | Some(b'|'))) =>
                {
                    // Captures in a quantified empty alternative use PCRE2's
                    // last-participating iteration rule, which differs from
                    // the automata engine's capture preference.
                    return Err(Error::unsupported(i, "empty alternative"));
                }
                byte => {
                    // PCRE extended mode keeps whitespace and `#` literal
                    // inside a class. Rust's extended syntax ignores them in
                    // classes too, so preserve PCRE's meaning explicitly.
                    if in_class
                        && (byte == b'&'
                            || byte == b'~'
                            || (byte == b'-'
                                && (bytes.get(i.wrapping_sub(1)) == Some(&b'-')
                                    || bytes.get(i + 1) == Some(&b'-'))))
                    {
                        // Prevent Rust character-class set operators from
                        // acquiring meaning absent from PCRE2 byte classes.
                        out.extend_from_slice(format!("\\x{byte:02X}").as_bytes());
                    } else if in_class && extended && (byte.is_ascii_whitespace() || byte == b'#') {
                        out.extend_from_slice(format!("\\x{byte:02X}").as_bytes());
                    } else {
                        out.push(byte);
                    }
                    i += 1;
                }
            }
        }
        if in_class {
            return Err(Error::syntax("unterminated character class"));
        }
        let pattern = String::from_utf8(out).expect("translation preserves UTF-8");
        Ok(Translation {
            complexity: pattern.len(),
            pattern,
            final_newline_fallback,
        })
    }

    fn append_quoted_literal(out: &mut Vec<u8>, literal: &str, extended: bool) {
        for ch in literal.chars() {
            if extended && ch.is_ascii() && (ch.is_ascii_whitespace() || ch == '#') {
                out.extend_from_slice(format!("\\x{:02X}", ch as u8).as_bytes());
            } else {
                out.extend_from_slice(regex::escape(&ch.to_string()).as_bytes());
            }
        }
    }

    /// PCRE2 diagnoses a quantifier without a preceding repeatable atom.
    /// Rust regex intentionally accepts some of these metacharacters as
    /// literals, so validate PCRE placement before handing off to its parser.
    fn invalid_quantifier_placement(pattern: &str, extended: bool) -> Option<usize> {
        let bytes = pattern.as_bytes();
        let mut i = 0;
        let mut repeatable = false;
        let mut in_class = false;
        while i < bytes.len() {
            if in_class {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                } else {
                    if bytes[i] == b']' {
                        in_class = false;
                        repeatable = true;
                    }
                    i += 1;
                }
                continue;
            }
            if extended && bytes[i].is_ascii_whitespace() {
                i += 1;
                continue;
            }
            if extended && bytes[i] == b'#' {
                i = bytes[i..]
                    .iter()
                    .position(|&byte| byte == b'\n')
                    .map_or(bytes.len(), |relative| i + relative + 1);
                continue;
            }
            match bytes[i] {
                b'[' => {
                    in_class = true;
                    i += 1;
                }
                b'\\' => {
                    let Some(&escaped) = bytes.get(i + 1) else {
                        return None;
                    };
                    if escaped == b'Q' {
                        let start = i + 2;
                        let end = bytes[start..]
                            .windows(2)
                            .position(|pair| pair == b"\\E")
                            .map_or(bytes.len(), |relative| start + relative);
                        if end > start {
                            repeatable = true;
                        }
                        i = if end < bytes.len() { end + 2 } else { end };
                    } else {
                        repeatable =
                            !matches!(escaped, b'A' | b'B' | b'G' | b'K' | b'Z' | b'b' | b'z');
                        i = (i + 2).min(bytes.len());
                    }
                }
                b'(' => {
                    if bytes[i..].starts_with(b"(?#") {
                        let end = bytes[i + 3..]
                            .iter()
                            .position(|&byte| byte == b')')
                            .map_or(bytes.len(), |relative| i + 4 + relative);
                        i = end;
                        continue;
                    }
                    repeatable = false;
                    i += 1;
                    if bytes.get(i) == Some(&b'?') {
                        i += 1;
                        if bytes.get(i) == Some(&b'P') && bytes.get(i + 1) == Some(&b'<') {
                            i += 2;
                            while i < bytes.len() && bytes[i] != b'>' {
                                i += 1;
                            }
                            i = (i + 1).min(bytes.len());
                        } else if bytes.get(i) == Some(&b'<')
                            && !matches!(bytes.get(i + 1), Some(b'=') | Some(b'!'))
                        {
                            i += 1;
                            while i < bytes.len() && bytes[i] != b'>' {
                                i += 1;
                            }
                            i = (i + 1).min(bytes.len());
                        } else if bytes.get(i) == Some(&b'\'') {
                            i += 1;
                            while i < bytes.len() && bytes[i] != b'\'' {
                                i += 1;
                            }
                            i = (i + 1).min(bytes.len());
                        } else if bytes.get(i) == Some(&b':') {
                            i += 1;
                        } else if bytes
                            .get(i)
                            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'-')
                        {
                            while i < bytes.len()
                                && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'-')
                            {
                                i += 1;
                            }
                            if matches!(bytes.get(i), Some(b':') | Some(b')')) {
                                i += 1;
                            }
                        }
                    }
                }
                b')' => {
                    repeatable = true;
                    i += 1;
                }
                b'^' | b'$' | b'|' => {
                    repeatable = false;
                    i += 1;
                }
                b'*' | b'+' | b'?' => {
                    if !repeatable {
                        return Some(i);
                    }
                    i += 1;
                    if matches!(bytes.get(i), Some(b'?') | Some(b'+')) {
                        i += 1;
                    }
                    repeatable = false;
                }
                b'{' if quantifier_end(&bytes[i..]).is_some() => {
                    if !repeatable {
                        return Some(i);
                    }
                    i += quantifier_end(&bytes[i..]).unwrap_or(1);
                    if matches!(bytes.get(i), Some(b'?') | Some(b'+')) {
                        i += 1;
                    }
                    repeatable = false;
                }
                _ => {
                    repeatable = true;
                    i += 1;
                }
            }
        }
        None
    }

    fn quantifier_end(bytes: &[u8]) -> Option<usize> {
        if bytes.first() != Some(&b'{') {
            return None;
        }
        let close = bytes.iter().position(|&byte| byte == b'}')?;
        let body = &bytes[1..close];
        let valid = !body.is_empty()
            && body
                .iter()
                .all(|byte| byte.is_ascii_digit() || *byte == b',')
            && body.iter().filter(|&&byte| byte == b',').count() <= 1
            && body.iter().any(u8::is_ascii_digit);
        valid.then_some(close + 1)
    }

    fn ambiguous_nested_capture_repeat(pattern: &str) -> Option<usize> {
        let bytes = pattern.as_bytes();
        let mut stack: Vec<(usize, bool)> = Vec::new();
        let mut class = false;
        let mut escaped = false;
        for (index, &byte) in bytes.iter().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }
            if byte == b'\\' {
                escaped = true;
                continue;
            }
            if byte == b'[' && !class {
                class = true;
                continue;
            }
            if byte == b']' && class {
                class = false;
                continue;
            }
            if class {
                continue;
            }
            if byte == b'(' {
                let capturing = !bytes[index..].starts_with(b"(?:")
                    && !bytes[index..].starts_with(b"(?#")
                    && !bytes[index..].starts_with(b"(?=")
                    && !bytes[index..].starts_with(b"(?!")
                    && !bytes[index..].starts_with(b"(?<=")
                    && !bytes[index..].starts_with(b"(?<!");
                stack.push((index, capturing));
                continue;
            }
            if byte != b')' {
                continue;
            }
            let Some((start, capturing)) = stack.pop() else {
                continue;
            };
            if !capturing || !matches!(bytes.get(index + 1), Some(b'*' | b'+' | b'?' | b'{')) {
                continue;
            }
            if bytes[start + 1..index]
                .iter()
                .any(|byte| matches!(byte, b'*' | b'+' | b'?' | b'{'))
            {
                return Some(index + 1);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::bytes::{Regex, RegexBuilder};
    use super::ErrorKind;

    #[test]
    fn pcre_regular_extensions_and_captures() {
        assert!(Regex::new(r"\Qsecret.txt\E\Z")
            .unwrap()
            .is_match(b"secret.txt")
            .unwrap());
        assert!(Regex::new(r"sec(?# ignored)ret")
            .unwrap()
            .is_match(b"secret")
            .unwrap());
        let regex = Regex::new(r"pre\K(?<value>secret)").unwrap();
        let captures = regex.captures(b"presecret").unwrap().unwrap();
        assert_eq!(captures.get(0).unwrap().as_bytes(), b"secret");
        assert_eq!(captures.name("value").unwrap().as_bytes(), b"secret");
        assert_eq!(regex.captures_len(), 2);
    }

    #[test]
    fn backtracking_constructs_fail_closed() {
        for pattern in [r"(a)\1", r"(?=a)a", r"(?>a)", r"a++", r"(?R)"] {
            let error = Regex::new(pattern).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Unsupported, "{pattern}: {error}");
        }
        let mut builder = RegexBuilder::new();
        builder.backtracking(true);
        assert_eq!(
            builder.build("a").unwrap_err().kind(),
            ErrorKind::ResourceLimit
        );
        assert_eq!(Regex::new("^?<wo").unwrap_err().kind(), ErrorKind::Syntax);
    }

    #[test]
    fn resource_limits_are_errors_not_partial_matches() {
        let mut builder = RegexBuilder::new();
        builder.max_subject_size(3).match_limit(32);
        let regex = builder.build("a+").unwrap();
        assert!(regex.is_match(b"aaa").unwrap());
        assert_eq!(
            regex.is_match(b"aaaa").unwrap_err().kind(),
            ErrorKind::ResourceLimit
        );
    }

    #[test]
    fn iterators_advance_after_empty_matches() {
        let regex = Regex::new("a*").unwrap();
        let matches: Vec<_> = regex
            .find_iter(b"bb")
            .map(|result| {
                let matched = result.unwrap();
                (matched.start(), matched.end())
            })
            .collect();
        assert_eq!(matches, vec![(0, 0), (1, 1), (2, 2)]);

        let adjacent = Regex::new("a*").unwrap();
        let matches: Vec<_> = adjacent
            .find_iter(b"a")
            .map(|result| {
                let matched = result.unwrap();
                (matched.start(), matched.end())
            })
            .collect();
        assert_eq!(matches, vec![(0, 1)]);
    }
}
