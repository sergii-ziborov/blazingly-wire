#![forbid(unsafe_code)]

//! Framework-independent HTTP/1 parsing and response framing.
//!
//! This crate owns no socket runtime and has no dependency on Blazingly
//! contracts, routing, execution, `OpenAPI`, or `MCP`. Adapters provide bytes and
//! choose how reads, writes, scheduling, and application dispatch happen.

use std::fmt;
use std::io;

pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_HEADER_BYTES: usize = 32 * 1024;
pub const DEFAULT_MAX_HEADERS: usize = 64;
pub const DEFAULT_MAX_CHUNKS: usize = 8 * 1024;
pub const MAX_HEADER_CAPACITY: usize = 128;
const INLINE_REQUEST_HEADERS: usize = 16;

/// Limits enforced while decoding one HTTP/1 request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    header_bytes: usize,
    headers: usize,
    body_bytes: usize,
    chunks: usize,
}

impl Limits {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            header_bytes: DEFAULT_MAX_HEADER_BYTES,
            headers: DEFAULT_MAX_HEADERS,
            body_bytes: DEFAULT_MAX_BODY_BYTES,
            chunks: DEFAULT_MAX_CHUNKS,
        }
    }

    #[must_use]
    pub const fn with_max_header_bytes(mut self, bytes: usize) -> Self {
        assert!(bytes > 0, "max_header_bytes must be greater than zero");
        self.header_bytes = bytes;
        self
    }

    #[must_use]
    pub const fn with_max_headers(mut self, count: usize) -> Self {
        assert!(count > 0, "max_headers must be greater than zero");
        assert!(
            count <= MAX_HEADER_CAPACITY,
            "max_headers cannot exceed the parser stack capacity"
        );
        self.headers = count;
        self
    }

    #[must_use]
    pub const fn with_max_body_bytes(mut self, bytes: usize) -> Self {
        self.body_bytes = bytes;
        self
    }

    #[must_use]
    pub const fn with_max_chunks(mut self, count: usize) -> Self {
        assert!(count > 0, "max_chunks must be greater than zero");
        self.chunks = count;
        self
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::new()
    }
}

/// Standard HTTP methods accepted by the current parser.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
    Trace,
    Connect,
}

impl Method {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
        }
    }

    /// Parses one standard HTTP method token.
    ///
    /// # Errors
    ///
    /// Returns a method-not-allowed protocol rejection for unsupported tokens.
    pub fn parse(method: &str) -> Result<Self, ParseError> {
        match method {
            "GET" => Ok(Self::Get),
            "HEAD" => Ok(Self::Head),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "PATCH" => Ok(Self::Patch),
            "DELETE" => Ok(Self::Delete),
            "OPTIONS" => Ok(Self::Options),
            "TRACE" => Ok(Self::Trace),
            "CONNECT" => Ok(Self::Connect),
            _ => Err(ParseError {
                status: 405,
                code: "method_not_allowed",
                message: "HTTP method is not supported by this build",
            }),
        }
    }
}

/// Byte range referencing the caller-owned receive buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}

impl ByteRange {
    #[must_use]
    pub fn bytes(self, buffer: &[u8]) -> Option<&[u8]> {
        buffer.get(self.start..self.end)
    }

    #[must_use]
    pub fn text(self, buffer: &[u8]) -> Option<&str> {
        std::str::from_utf8(self.bytes(buffer)?).ok()
    }
}

/// Header name and value ranges in the caller-owned receive buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderPosition {
    pub name: ByteRange,
    pub value: ByteRange,
}

const EMPTY_HEADER_POSITION: HeaderPosition = HeaderPosition {
    name: ByteRange { start: 0, end: 0 },
    value: ByteRange { start: 0, end: 0 },
};

/// Inline-first header positions parsed without copying header bytes.
#[derive(Clone, Debug)]
pub struct HeaderPositions {
    inline: [HeaderPosition; INLINE_REQUEST_HEADERS],
    inline_len: usize,
    overflow: Vec<HeaderPosition>,
}

impl HeaderPositions {
    fn new() -> Self {
        Self {
            inline: [EMPTY_HEADER_POSITION; INLINE_REQUEST_HEADERS],
            inline_len: 0,
            overflow: Vec::new(),
        }
    }

    fn push(&mut self, header: HeaderPosition) {
        if self.inline_len < INLINE_REQUEST_HEADERS {
            self.inline[self.inline_len] = header;
            self.inline_len += 1;
        } else {
            self.overflow.push(header);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = HeaderPosition> + '_ {
        self.inline[..self.inline_len]
            .iter()
            .copied()
            .chain(self.overflow.iter().copied())
    }

    #[must_use]
    pub fn value<'buffer>(
        &self,
        buffer: &'buffer [u8],
        name: &str,
        index: usize,
    ) -> Option<&'buffer str> {
        self.iter()
            .filter(|header| {
                header
                    .name
                    .text(buffer)
                    .is_some_and(|header| header_name_matches(header, name))
            })
            .nth(index)?
            .value
            .text(buffer)
    }
}

/// Request body framing selected from validated HTTP/1 headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyFraming {
    ContentLength(usize),
    Chunked,
}

/// Parsed request head borrowing all text through byte ranges.
#[derive(Clone, Debug)]
pub struct RequestHead {
    pub method: Method,
    pub target: ByteRange,
    pub headers: HeaderPositions,
    pub head_bytes: usize,
    pub body: BodyFraming,
    pub keep_alive: bool,
}

/// Stable protocol rejection suitable for an adapter error response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseError {
    pub status: u16,
    pub code: &'static str,
    pub message: &'static str,
}

impl ParseError {
    const fn bad_request() -> Self {
        Self {
            status: 400,
            code: "bad_request",
            message: "invalid HTTP/1 request",
        }
    }

    const fn headers_too_large() -> Self {
        Self {
            status: 431,
            code: "request_header_too_large",
            message: "request headers exceed the configured limit",
        }
    }

    const fn payload_too_large() -> Self {
        Self {
            status: 413,
            code: "payload_too_large",
            message: "request body exceeds the configured limit",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Parses one complete HTTP/1 request head from the start of `buffer`.
///
/// `Ok(None)` means more bytes are required. Returned ranges remain valid only
/// while the caller preserves the buffer prefix.
///
/// # Errors
///
/// Returns a bounded protocol rejection for malformed or oversized headers,
/// conflicting framing fields, unsupported transfer encodings, and methods.
pub fn parse_request_head(
    buffer: &[u8],
    limits: Limits,
) -> Result<Option<RequestHead>, ParseError> {
    let mut inline = [httparse::EMPTY_HEADER; INLINE_REQUEST_HEADERS];
    let inline_limit = limits.headers.min(INLINE_REQUEST_HEADERS);
    match parse_head_with_headers(buffer, limits, &mut inline[..inline_limit]) {
        Err(rejection) if rejection.status == 431 && limits.headers > INLINE_REQUEST_HEADERS => {
            let mut overflow = [httparse::EMPTY_HEADER; MAX_HEADER_CAPACITY];
            parse_head_with_headers(buffer, limits, &mut overflow[..limits.headers])
        }
        result => result,
    }
}

fn parse_head_with_headers<'buffer>(
    buffer: &'buffer [u8],
    limits: Limits,
    headers: &mut [httparse::Header<'buffer>],
) -> Result<Option<RequestHead>, ParseError> {
    let mut request = httparse::Request::new(headers);
    let status = request.parse(buffer).map_err(|error| match error {
        httparse::Error::TooManyHeaders => ParseError::headers_too_large(),
        _ => ParseError::bad_request(),
    })?;
    let httparse::Status::Complete(head_bytes) = status else {
        if buffer.len() > limits.header_bytes {
            return Err(ParseError::headers_too_large());
        }
        return Ok(None);
    };
    if head_bytes > limits.header_bytes {
        return Err(ParseError::headers_too_large());
    }
    let method = Method::parse(request.method.ok_or_else(ParseError::bad_request)?)?;
    let target = byte_range(
        buffer,
        request.path.ok_or_else(ParseError::bad_request)?.as_bytes(),
    )?;
    let version = request.version.ok_or_else(ParseError::bad_request)?;

    let mut content_length = None;
    let mut connection_close = false;
    let mut connection_keep_alive = false;
    let mut transfer_encoding_tokens = 0_usize;
    let mut transfer_encoding_chunked = false;
    let mut parsed_headers = HeaderPositions::new();
    for header in request.headers.iter() {
        parsed_headers.push(HeaderPosition {
            name: byte_range(buffer, header.name.as_bytes())?,
            value: byte_range(buffer, header.value)?,
        });
        // Length gate before case-insensitive comparison; values of framing
        // headers stay fully validated, other values are validated lazily on
        // lookup.
        match header.name.len() {
            14 if header.name.eq_ignore_ascii_case("content-length") => {
                let length = parse_content_length(header.value)?;
                if content_length.is_some_and(|previous| previous != length) {
                    return Err(ParseError::bad_request());
                }
                content_length = Some(length);
            }
            17 if header.name.eq_ignore_ascii_case("transfer-encoding") => {
                if header.value.eq_ignore_ascii_case(b"chunked") {
                    transfer_encoding_tokens += 1;
                    transfer_encoding_chunked = transfer_encoding_tokens == 1;
                } else {
                    let value =
                        std::str::from_utf8(header.value).map_err(|_| ParseError::bad_request())?;
                    for token in value.split(',').map(str::trim) {
                        if token.is_empty() {
                            continue;
                        }
                        transfer_encoding_tokens += 1;
                        transfer_encoding_chunked =
                            transfer_encoding_tokens == 1 && token.eq_ignore_ascii_case("chunked");
                    }
                }
            }
            10 if header.name.eq_ignore_ascii_case("connection") => {
                if header.value.eq_ignore_ascii_case(b"keep-alive") {
                    connection_keep_alive = true;
                } else if header.value.eq_ignore_ascii_case(b"close") {
                    connection_close = true;
                } else {
                    let value =
                        std::str::from_utf8(header.value).map_err(|_| ParseError::bad_request())?;
                    for token in value.split(',').map(str::trim) {
                        connection_close |= token.eq_ignore_ascii_case("close");
                        connection_keep_alive |= token.eq_ignore_ascii_case("keep-alive");
                    }
                }
            }
            _ => {}
        }
    }

    if transfer_encoding_tokens > 0 && content_length.is_some() {
        return Err(ParseError::bad_request());
    }
    let body = if transfer_encoding_tokens == 0 {
        BodyFraming::ContentLength(content_length.unwrap_or(0))
    } else if transfer_encoding_chunked {
        BodyFraming::Chunked
    } else {
        return Err(ParseError {
            status: 501,
            code: "unsupported_transfer_encoding",
            message: "only chunked transfer encoding is supported",
        });
    };

    Ok(Some(RequestHead {
        method,
        target,
        headers: parsed_headers,
        head_bytes,
        body,
        keep_alive: if version == 1 {
            !connection_close
        } else {
            connection_keep_alive && !connection_close
        },
    }))
}

/// Incremental decoder for a chunked request body and optional trailers.
#[derive(Debug)]
pub struct ChunkDecoder {
    position: usize,
    pending_size: Option<usize>,
    body: Vec<u8>,
    max_body_bytes: usize,
    max_header_bytes: usize,
    max_chunks: usize,
    chunks: usize,
}

impl ChunkDecoder {
    #[must_use]
    pub fn new(position: usize, limits: Limits) -> Self {
        Self {
            position,
            pending_size: None,
            body: Vec::new(),
            max_body_bytes: limits.body_bytes,
            max_header_bytes: limits.header_bytes,
            max_chunks: limits.chunks,
            chunks: 0,
        }
    }

    /// Advances decoding over the caller's accumulated receive buffer.
    ///
    /// # Errors
    ///
    /// Returns a protocol rejection for malformed chunks/trailers or configured
    /// body, trailer, and chunk-count limit violations.
    pub fn advance(&mut self, buffer: &[u8]) -> Result<Option<DecodedChunkedBody>, ParseError> {
        loop {
            if let Some(size) = self.pending_size {
                let end = self
                    .position
                    .checked_add(size)
                    .ok_or_else(ParseError::bad_request)?;
                let chunk_end = end.checked_add(2).ok_or_else(ParseError::bad_request)?;
                if buffer.len() < chunk_end {
                    return Ok(None);
                }
                if buffer.get(end..chunk_end) != Some(b"\r\n") {
                    return Err(ParseError::bad_request());
                }
                self.body.extend_from_slice(&buffer[self.position..end]);
                self.position = chunk_end;
                self.pending_size = None;
                continue;
            }

            let Some(line_end) = find_bytes(buffer, b"\r\n", self.position) else {
                if buffer.len().saturating_sub(self.position) > self.max_header_bytes {
                    return Err(ParseError::bad_request());
                }
                return Ok(None);
            };
            let size_line = std::str::from_utf8(&buffer[self.position..line_end])
                .map_err(|_| ParseError::bad_request())?;
            let size = size_line
                .split(';')
                .next()
                .map(str::trim)
                .filter(|size| !size.is_empty())
                .and_then(|size| usize::from_str_radix(size, 16).ok())
                .ok_or_else(ParseError::bad_request)?;
            self.position = line_end + 2;

            if size == 0 {
                let consumed = if buffer.get(self.position..self.position + 2) == Some(b"\r\n") {
                    self.position + 2
                } else {
                    let Some(trailer_end) = find_bytes(buffer, b"\r\n\r\n", self.position) else {
                        if buffer.len().saturating_sub(self.position) > self.max_header_bytes {
                            return Err(ParseError::headers_too_large());
                        }
                        return Ok(None);
                    };
                    if trailer_end - self.position > self.max_header_bytes {
                        return Err(ParseError::headers_too_large());
                    }
                    validate_trailers(&buffer[self.position..trailer_end])?;
                    trailer_end + 4
                };
                return Ok(Some(DecodedChunkedBody {
                    consumed,
                    body: std::mem::take(&mut self.body),
                }));
            }

            if size > self.max_body_bytes.saturating_sub(self.body.len()) {
                return Err(ParseError::payload_too_large());
            }
            self.chunks += 1;
            if self.chunks > self.max_chunks {
                return Err(ParseError {
                    status: 413,
                    code: "too_many_chunks",
                    message: "chunk count exceeds the configured limit",
                });
            }
            self.pending_size = Some(size);
        }
    }
}

/// One incremental event from [`StreamingChunkDecoder`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamingChunk {
    /// More receive bytes are required.
    NeedMore,
    /// One decoded data chunk referencing the caller-owned receive buffer.
    Data(ByteRange),
    /// Final chunk and trailers were validated.
    Complete { consumed: usize },
}

/// Zero-aggregate incremental chunked decoder for streaming request bodies.
///
/// Unlike [`ChunkDecoder`], this decoder never builds a complete body. Each
/// returned range can be copied into a bounded transport channel and released
/// before reading the next network chunk.
#[derive(Debug)]
pub struct StreamingChunkDecoder {
    position: usize,
    pending_size: Option<usize>,
    body_bytes: usize,
    max_body_bytes: usize,
    max_header_bytes: usize,
    max_chunks: usize,
    chunks: usize,
}

impl StreamingChunkDecoder {
    #[must_use]
    pub fn new(position: usize, limits: Limits) -> Self {
        Self {
            position,
            pending_size: None,
            body_bytes: 0,
            max_body_bytes: limits.body_bytes,
            max_header_bytes: limits.header_bytes,
            max_chunks: limits.chunks,
            chunks: 0,
        }
    }

    /// Advances by at most one decoded data chunk.
    ///
    /// # Errors
    ///
    /// Returns a bounded protocol rejection for malformed chunks/trailers or
    /// configured body and chunk-count limit violations.
    pub fn advance(&mut self, buffer: &[u8]) -> Result<StreamingChunk, ParseError> {
        loop {
            if let Some(remaining) = self.pending_size {
                if remaining > 0 {
                    let available = buffer.len().saturating_sub(self.position).min(remaining);
                    if available == 0 {
                        return Ok(StreamingChunk::NeedMore);
                    }
                    let end = self
                        .position
                        .checked_add(available)
                        .ok_or_else(ParseError::bad_request)?;
                    let data = ByteRange {
                        start: self.position,
                        end,
                    };
                    self.position = end;
                    self.pending_size = Some(remaining - available);
                    return Ok(StreamingChunk::Data(data));
                }
                let chunk_end = self
                    .position
                    .checked_add(2)
                    .ok_or_else(ParseError::bad_request)?;
                if buffer.len() < chunk_end {
                    return Ok(StreamingChunk::NeedMore);
                }
                if buffer.get(self.position..chunk_end) != Some(b"\r\n") {
                    return Err(ParseError::bad_request());
                }
                self.position = chunk_end;
                self.pending_size = None;
                continue;
            }

            let Some(line_end) = find_bytes(buffer, b"\r\n", self.position) else {
                if buffer.len().saturating_sub(self.position) > self.max_header_bytes {
                    return Err(ParseError::bad_request());
                }
                return Ok(StreamingChunk::NeedMore);
            };
            let size_line = std::str::from_utf8(&buffer[self.position..line_end])
                .map_err(|_| ParseError::bad_request())?;
            let size = size_line
                .split(';')
                .next()
                .map(str::trim)
                .filter(|size| !size.is_empty())
                .and_then(|size| usize::from_str_radix(size, 16).ok())
                .ok_or_else(ParseError::bad_request)?;
            self.position = line_end + 2;

            if size == 0 {
                let consumed = if buffer.get(self.position..self.position + 2) == Some(b"\r\n") {
                    self.position + 2
                } else {
                    let Some(trailer_end) = find_bytes(buffer, b"\r\n\r\n", self.position) else {
                        if buffer.len().saturating_sub(self.position) > self.max_header_bytes {
                            return Err(ParseError::headers_too_large());
                        }
                        return Ok(StreamingChunk::NeedMore);
                    };
                    if trailer_end - self.position > self.max_header_bytes {
                        return Err(ParseError::headers_too_large());
                    }
                    validate_trailers(&buffer[self.position..trailer_end])?;
                    trailer_end + 4
                };
                return Ok(StreamingChunk::Complete { consumed });
            }

            if size > self.max_body_bytes.saturating_sub(self.body_bytes) {
                return Err(ParseError::payload_too_large());
            }
            self.body_bytes += size;
            self.chunks += 1;
            if self.chunks > self.max_chunks {
                return Err(ParseError {
                    status: 413,
                    code: "too_many_chunks",
                    message: "chunk count exceeds the configured limit",
                });
            }
            self.pending_size = Some(size);
        }
    }

    #[must_use]
    pub const fn body_bytes(&self) -> usize {
        self.body_bytes
    }

    /// Wire prefix fully consumed by emitted events.
    #[must_use]
    pub const fn consumed_prefix(&self) -> usize {
        self.position
    }

    /// Rebases decoder offsets after the caller discards a consumed prefix.
    ///
    /// # Panics
    ///
    /// Panics when `bytes` exceeds [`Self::consumed_prefix`].
    pub fn discard_prefix(&mut self, bytes: usize) {
        assert!(
            bytes <= self.position,
            "cannot discard bytes the decoder has not consumed"
        );
        self.position -= bytes;
    }
}

/// Complete decoded chunked body and total consumed wire bytes.
#[derive(Debug, Eq, PartialEq)]
pub struct DecodedChunkedBody {
    pub consumed: usize,
    pub body: Vec<u8>,
}

/// Encodes an HTTP/1 response head while filtering caller-supplied framing
/// fields. The adapter remains responsible for writing buffered/streaming body
/// bytes and chunk terminators.
///
/// # Errors
///
/// Returns an invalid-input error for unsafe header names, values, or date.
#[allow(clippy::too_many_arguments)]
pub fn encode_response_head<'headers>(
    output: &mut Vec<u8>,
    status: u16,
    headers: impl IntoIterator<Item = (&'headers str, &'headers str)>,
    content_length: Option<u64>,
    chunked: bool,
    keep_alive: bool,
    date: &str,
) -> io::Result<()> {
    push_status_line(output, status);
    let mut has_date = false;
    for (name, value) in headers {
        if is_framing_header(name) {
            continue;
        }
        if !valid_header(name, value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "response contains an invalid header",
            ));
        }
        has_date |= name.len() == 4 && name.eq_ignore_ascii_case("date");
        push_header(output, name, value);
    }
    push_framing_tail(output, content_length, chunked, keep_alive, date, has_date)
}

/// Response headers validated and encoded once for reuse across responses.
///
/// [`encode_response_head`] re-validates every header on every call, which is
/// the right default for uncontrolled input. When the same header set is sent
/// many times, prepare it once and encode each response with
/// [`encode_response_head_prepared`].
#[derive(Clone, Debug)]
pub struct PreparedHeaders {
    encoded: Vec<u8>,
    has_date: bool,
}

impl PreparedHeaders {
    /// Validates response headers once, filtering caller-supplied framing
    /// fields exactly like [`encode_response_head`].
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error for unsafe header names/values.
    pub fn new<'headers>(
        headers: impl IntoIterator<Item = (&'headers str, &'headers str)>,
    ) -> io::Result<Self> {
        let mut encoded = Vec::new();
        let mut has_date = false;
        for (name, value) in headers {
            if is_framing_header(name) {
                continue;
            }
            if !valid_header(name, value) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "response contains an invalid header",
                ));
            }
            has_date |= name.len() == 4 && name.eq_ignore_ascii_case("date");
            push_header(&mut encoded, name, value);
        }
        Ok(Self { encoded, has_date })
    }
}

/// Encodes an HTTP/1 response head from pre-validated headers.
///
/// Framing behavior matches [`encode_response_head`]; per-header validation
/// was already paid once in [`PreparedHeaders::new`].
///
/// # Errors
///
/// Returns an invalid-input error for an unsafe `date` value.
pub fn encode_response_head_prepared(
    output: &mut Vec<u8>,
    status: u16,
    headers: &PreparedHeaders,
    content_length: Option<u64>,
    chunked: bool,
    keep_alive: bool,
    date: &str,
) -> io::Result<()> {
    push_status_line(output, status);
    output.extend_from_slice(&headers.encoded);
    push_framing_tail(
        output,
        content_length,
        chunked,
        keep_alive,
        date,
        headers.has_date,
    )
}

fn push_status_line(output: &mut Vec<u8>, status: u16) {
    let reason = reason_phrase(status).as_bytes();
    let mut digits = [0_u8; 20];
    let start = write_decimal(u64::from(status), &mut digits);
    let count = digits.len() - start;
    // Longest reason phrase is 31 bytes; 64 leaves headroom for new phrases.
    let mut line = [0_u8; 64];
    line[..9].copy_from_slice(b"HTTP/1.1 ");
    let mut cursor = 9;
    line[cursor..cursor + count].copy_from_slice(&digits[start..]);
    cursor += count;
    line[cursor] = b' ';
    cursor += 1;
    line[cursor..cursor + reason.len()].copy_from_slice(reason);
    cursor += reason.len();
    line[cursor] = b'\r';
    line[cursor + 1] = b'\n';
    output.extend_from_slice(&line[..cursor + 2]);
}

fn push_framing_tail(
    output: &mut Vec<u8>,
    content_length: Option<u64>,
    chunked: bool,
    keep_alive: bool,
    date: &str,
    has_date: bool,
) -> io::Result<()> {
    if let Some(length) = content_length {
        push_content_length_line(output, length);
    } else if chunked {
        output.extend_from_slice(b"transfer-encoding: chunked\r\n");
    }
    if !has_date {
        if !valid_header_value(date) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "response date is invalid",
            ));
        }
        push_date_line(output, date);
    }
    if !keep_alive {
        output.extend_from_slice(b"connection: close\r\n");
    }
    output.extend_from_slice(b"\r\n");
    Ok(())
}

fn push_date_line(output: &mut Vec<u8>, date: &str) {
    const PREFIX: &[u8; 6] = b"date: ";
    let date = date.as_bytes();
    let mut line = [0_u8; 64];
    if date.len() <= line.len() - PREFIX.len() - 2 {
        let mut cursor = append(&mut line, 0, PREFIX);
        cursor = append(&mut line, cursor, date);
        cursor = append(&mut line, cursor, b"\r\n");
        output.extend_from_slice(&line[..cursor]);
    } else {
        output.extend_from_slice(PREFIX);
        output.extend_from_slice(date);
        output.extend_from_slice(b"\r\n");
    }
}

fn is_framing_header(name: &str) -> bool {
    match name.len() {
        10 => name.eq_ignore_ascii_case("connection"),
        14 => name.eq_ignore_ascii_case("content-length"),
        17 => name.eq_ignore_ascii_case("transfer-encoding"),
        _ => false,
    }
}

fn push_header(output: &mut Vec<u8>, name: &str, value: &str) {
    output.extend_from_slice(name.as_bytes());
    output.extend_from_slice(b": ");
    output.extend_from_slice(value.as_bytes());
    output.extend_from_slice(b"\r\n");
}

fn append<const CAPACITY: usize>(
    buffer: &mut [u8; CAPACITY],
    cursor: usize,
    bytes: &[u8],
) -> usize {
    buffer[cursor..cursor + bytes.len()].copy_from_slice(bytes);
    cursor + bytes.len()
}

/// Writes `value` right-aligned into `digits`; returns the first used index.
fn write_decimal(mut value: u64, digits: &mut [u8; 20]) -> usize {
    let mut cursor = digits.len();
    loop {
        cursor -= 1;
        #[allow(clippy::cast_possible_truncation)] // remainder < 10
        {
            digits[cursor] = b'0' + (value % 10) as u8;
        }
        value /= 10;
        if value == 0 {
            break;
        }
    }
    cursor
}

fn push_content_length_line(output: &mut Vec<u8>, length: u64) {
    const PREFIX: &[u8; 16] = b"content-length: ";
    let mut digits = [0_u8; 20];
    let start = write_decimal(length, &mut digits);
    let count = digits.len() - start;
    let mut line = [0_u8; PREFIX.len() + 20 + 2];
    line[..PREFIX.len()].copy_from_slice(PREFIX);
    line[PREFIX.len()..PREFIX.len() + count].copy_from_slice(&digits[start..]);
    line[PREFIX.len() + count] = b'\r';
    line[PREFIX.len() + count + 1] = b'\n';
    output.extend_from_slice(&line[..PREFIX.len() + count + 2]);
}

fn push_hex(output: &mut Vec<u8>, mut value: usize) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut digits = [0_u8; usize::BITS as usize / 4];
    let mut cursor = digits.len();
    loop {
        cursor -= 1;
        digits[cursor] = HEX[value & 0xF];
        value >>= 4;
        if value == 0 {
            break;
        }
    }
    output.extend_from_slice(&digits[cursor..]);
}

/// Encodes a `101 Switching Protocols` response without HTTP body framing.
///
/// # Errors
///
/// Returns an invalid-input error unless safe `Connection: Upgrade` and
/// `Upgrade` headers are present.
pub fn encode_upgrade_response<'headers>(
    output: &mut Vec<u8>,
    headers: impl IntoIterator<Item = (&'headers str, &'headers str)>,
    date: &str,
) -> io::Result<()> {
    output.extend_from_slice(b"HTTP/1.1 101 Switching Protocols\r\n");
    let mut has_connection_upgrade = false;
    let mut has_upgrade = false;
    let mut has_date = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        if !valid_header(name, value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "upgrade response contains an invalid header",
            ));
        }
        if name.eq_ignore_ascii_case("connection") {
            has_connection_upgrade |= value
                .split(',')
                .map(str::trim)
                .any(|token| token.eq_ignore_ascii_case("upgrade"));
        }
        has_upgrade |= name.eq_ignore_ascii_case("upgrade") && !value.trim().is_empty();
        has_date |= name.eq_ignore_ascii_case("date");
        push_header(output, name, value);
    }
    if !has_connection_upgrade || !has_upgrade {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "upgrade response is missing required protocol switch headers",
        ));
    }
    if !has_date {
        if !valid_header_value(date) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "response date is invalid",
            ));
        }
        push_header(output, "date", date);
    }
    output.extend_from_slice(b"\r\n");
    Ok(())
}

/// Appends one HTTP/1 chunk frame to `output`.
///
/// # Errors
///
/// Never fails today; the `io::Result` return is kept for API stability.
pub fn encode_chunk(output: &mut Vec<u8>, chunk: &[u8]) -> io::Result<()> {
    push_hex(output, chunk.len());
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(chunk);
    output.extend_from_slice(b"\r\n");
    Ok(())
}

pub const LAST_CHUNK: &[u8] = b"0\r\n\r\n";

#[must_use]
pub const fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        499 => "Client Closed Request",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

fn byte_range(buffer: &[u8], slice: &[u8]) -> Result<ByteRange, ParseError> {
    let start = (slice.as_ptr() as usize)
        .checked_sub(buffer.as_ptr() as usize)
        .ok_or_else(ParseError::bad_request)?;
    let end = start
        .checked_add(slice.len())
        .filter(|end| *end <= buffer.len())
        .ok_or_else(ParseError::bad_request)?;
    Ok(ByteRange { start, end })
}

fn parse_content_length(value: &[u8]) -> Result<usize, ParseError> {
    // Digits-only fast path; whitespace-padded values take the tolerant path.
    if !value.is_empty() && value.len() <= 19 && value.iter().all(u8::is_ascii_digit) {
        let mut length = 0_u64;
        for &byte in value {
            length = length * 10 + u64::from(byte - b'0');
        }
        return usize::try_from(length).map_err(|_| ParseError::bad_request());
    }
    std::str::from_utf8(value)
        .map_err(|_| ParseError::bad_request())?
        .trim()
        .parse::<usize>()
        .map_err(|_| ParseError::bad_request())
}

fn validate_trailers(trailers: &[u8]) -> Result<(), ParseError> {
    let trailers = std::str::from_utf8(trailers).map_err(|_| ParseError::bad_request())?;
    for line in trailers.split("\r\n") {
        let (name, value) = line.split_once(':').ok_or_else(ParseError::bad_request)?;
        if name.is_empty() || !name.bytes().all(is_header_name_byte) || !valid_header_value(value) {
            return Err(ParseError::bad_request());
        }
    }
    Ok(())
}

fn find_bytes(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| from + position)
}

static HEADER_NAME_BYTES: [bool; 256] = {
    let mut table = [false; 256];
    let mut index = 0_usize;
    while index < 256 {
        #[allow(clippy::cast_possible_truncation)] // index < 256
        {
            table[index] = is_header_name_byte(index as u8);
        }
        index += 1;
    }
    table
};

fn valid_header(name: &str, value: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| HEADER_NAME_BYTES[usize::from(byte)])
        && valid_header_value(value)
}

/// Word-at-a-time scan flagging bytes below 0x20 (except HTAB) and DEL.
fn valid_header_value(value: &str) -> bool {
    const LOW: u64 = 0x0101_0101_0101_0101;
    const HIGH: u64 = 0x8080_8080_8080_8080;
    let mut chunks = value.as_bytes().chunks_exact(8);
    for chunk in chunks.by_ref() {
        let word = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
        let below_space = word.wrapping_sub(LOW * 0x20) & !word & HIGH;
        let tab = word ^ (LOW * u64::from(b'\t'));
        let tab = tab.wrapping_sub(LOW) & !tab & HIGH;
        let del = word ^ (LOW * 0x7F);
        let del = del.wrapping_sub(LOW) & !del & HIGH;
        if ((below_space & !tab) | del) != 0 {
            return false;
        }
    }
    chunks
        .remainder()
        .iter()
        .all(|&byte| byte == b'\t' || (byte >= b' ' && byte != 127))
}

const fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn header_name_matches(header: &str, argument: &str) -> bool {
    header
        .bytes()
        .map(|byte| byte.to_ascii_lowercase())
        .eq(argument
            .bytes()
            .map(|byte| if byte == b'_' { b'-' } else { byte })
            .map(|byte| byte.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::{
        BodyFraming, ChunkDecoder, Limits, Method, PreparedHeaders, StreamingChunk,
        StreamingChunkDecoder, encode_chunk, encode_response_head, encode_response_head_prepared,
        encode_upgrade_response, parse_request_head,
    };

    #[test]
    fn parses_borrowed_keep_alive_request_head() {
        let bytes =
            b"POST /items?x=1 HTTP/1.1\r\nHost: api.example\r\nContent-Length: 4\r\n\r\ntest";
        let head = parse_request_head(bytes, Limits::new())
            .expect("valid request")
            .expect("complete head");
        assert_eq!(head.method, Method::Post);
        assert_eq!(head.target.text(bytes), Some("/items?x=1"));
        assert_eq!(head.headers.value(bytes, "host", 0), Some("api.example"));
        assert_eq!(head.body, BodyFraming::ContentLength(4));
        assert!(head.keep_alive);
    }

    #[test]
    fn rejects_content_length_transfer_encoding_smuggling() {
        let bytes = b"POST / HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";
        let error = parse_request_head(bytes, Limits::new()).expect_err("must reject");
        assert_eq!(error.status, 400);
    }

    #[test]
    fn incrementally_decodes_chunked_body_and_trailers() {
        let bytes = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nx-id: 7\r\n\r\n";
        let head = parse_request_head(bytes, Limits::new())
            .expect("valid request")
            .expect("complete head");
        let mut decoder = ChunkDecoder::new(head.head_bytes, Limits::new());
        let body = decoder
            .advance(bytes)
            .expect("valid chunks")
            .expect("complete body");
        assert_eq!(body.body, b"test");
        assert_eq!(body.consumed, bytes.len());
    }

    #[test]
    fn streaming_decoder_yields_chunks_without_aggregating_the_body() {
        let bytes =
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n3\r\ning\r\n0\r\n\r\n";
        let head = parse_request_head(bytes, Limits::default())
            .expect("request")
            .expect("head");
        let mut decoder = StreamingChunkDecoder::new(head.head_bytes, Limits::default());
        let first = decoder.advance(bytes).expect("first");
        let StreamingChunk::Data(first) = first else {
            panic!("expected first chunk");
        };
        assert_eq!(first.bytes(bytes), Some(b"test".as_slice()));
        let second = decoder.advance(bytes).expect("second");
        let StreamingChunk::Data(second) = second else {
            panic!("expected second chunk");
        };
        assert_eq!(second.bytes(bytes), Some(b"ing".as_slice()));
        assert_eq!(
            decoder.advance(bytes).expect("complete"),
            StreamingChunk::Complete {
                consumed: bytes.len()
            }
        );
        assert_eq!(decoder.body_bytes(), 7);
    }

    #[test]
    fn response_head_owns_framing_and_blocks_header_injection() {
        let mut output = Vec::new();
        encode_response_head(
            &mut output,
            200,
            [("content-type", "application/json")],
            Some(2),
            false,
            true,
            "Mon, 27 Jul 2026 00:00:00 GMT",
        )
        .expect("valid response");
        let text = String::from_utf8(output).expect("HTTP text");
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("content-length: 2\r\n"));

        let mut invalid = Vec::new();
        assert!(
            encode_response_head(
                &mut invalid,
                200,
                [("x-value", "ok\r\ninjected: true")],
                Some(0),
                false,
                true,
                "Mon, 27 Jul 2026 00:00:00 GMT",
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_multi_token_transfer_encoding() {
        let bytes = b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        let error = parse_request_head(bytes, Limits::new()).expect_err("must reject");
        assert_eq!(error.status, 501);
    }

    #[test]
    fn parses_more_than_inline_headers_via_overflow() {
        let mut bytes = b"GET / HTTP/1.1\r\n".to_vec();
        for index in 0..20 {
            bytes.extend_from_slice(format!("x-h{index}: v{index}\r\n").as_bytes());
        }
        bytes.extend_from_slice(b"\r\n");
        let head = parse_request_head(&bytes, Limits::new().with_max_headers(32))
            .expect("valid request")
            .expect("complete head");
        assert_eq!(head.headers.iter().count(), 20);
        assert_eq!(head.headers.value(&bytes, "x-h0", 0), Some("v0"));
        assert_eq!(head.headers.value(&bytes, "x-h19", 0), Some("v19"));
    }

    #[test]
    fn prepared_headers_match_the_validating_path_and_stay_filtered() {
        let headers = [
            ("content-type", "application/json"),
            ("content-length", "999"),
            ("x-request-id", "abc123"),
        ];
        let date = "Mon, 27 Jul 2026 00:00:00 GMT";
        let mut per_call = Vec::new();
        encode_response_head(&mut per_call, 200, headers, Some(2), false, true, date)
            .expect("valid response");
        let prepared = PreparedHeaders::new(headers).expect("valid headers");
        let mut reused = Vec::new();
        encode_response_head_prepared(&mut reused, 200, &prepared, Some(2), false, true, date)
            .expect("valid response");
        assert_eq!(per_call, reused);
        assert!(
            !String::from_utf8(reused)
                .expect("HTTP text")
                .contains("999")
        );
        assert!(PreparedHeaders::new([("x-bad", "ok\r\ninjected: true")]).is_err());
    }

    #[test]
    fn prepared_caller_date_suppresses_the_generated_date() {
        let prepared =
            PreparedHeaders::new([("Date", "Mon, 27 Jul 2026 00:00:00 GMT")]).expect("valid");
        let mut output = Vec::new();
        encode_response_head_prepared(&mut output, 204, &prepared, None, false, true, "ignored")
            .expect("valid response");
        let text = String::from_utf8(output).expect("HTTP text");
        assert_eq!(text.matches("ate:").count(), 1);
    }

    #[test]
    fn value_validation_scans_full_words_and_remainders() {
        let accepts = |value: &str| {
            let mut output = Vec::new();
            encode_response_head(
                &mut output,
                200,
                [("x-v", value)],
                Some(0),
                false,
                true,
                "Mon, 27 Jul 2026 00:00:00 GMT",
            )
            .is_ok()
        };
        assert!(accepts("exactly-eight!!!"));
        assert!(accepts("tab\tinside a longer value"));
        assert!(accepts("caf\u{e9} obs-text value"));
        assert!(!accepts("bad\u{7f}in first word"));
        assert!(!accepts("eightpad\u{7f}tail"));
        assert!(!accepts("eightpadx\u{1f}"));
        assert!(!accepts("\u{1}"));
    }

    #[test]
    fn encodes_chunk_frames_with_uppercase_hex_sizes() {
        let mut output = Vec::new();
        encode_chunk(&mut output, &[b'x'; 26]).expect("chunk frame");
        assert!(output.starts_with(b"1A\r\n"));
        assert!(output.ends_with(b"\r\n"));
        assert_eq!(output.len(), 4 + 26 + 2);
    }

    #[test]
    fn switching_protocols_preserves_required_upgrade_headers() {
        let mut output = Vec::new();
        encode_upgrade_response(
            &mut output,
            [
                ("connection", "Upgrade"),
                ("upgrade", "websocket"),
                ("sec-websocket-accept", "accepted"),
            ],
            "Sun, 06 Nov 1994 08:49:37 GMT",
        )
        .expect("upgrade response");
        let output = String::from_utf8(output).expect("UTF-8");
        assert!(output.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(output.contains("connection: Upgrade\r\n"));
        assert!(!output.contains("content-length"));
    }
}
