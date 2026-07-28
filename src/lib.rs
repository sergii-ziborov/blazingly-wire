#![forbid(unsafe_code)]

//! Framework-independent HTTP/1 parsing and response framing.
//!
//! This crate owns no socket runtime and has no dependency on Blazingly
//! contracts, routing, execution, `OpenAPI`, or `MCP`. Adapters provide bytes and
//! choose how reads, writes, scheduling, and application dispatch happen.

use std::fmt;
use std::io::{self, Write as _};

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

/// Inline-first header positions parsed without copying header bytes.
#[derive(Clone, Debug)]
pub struct HeaderPositions {
    inline: [Option<HeaderPosition>; INLINE_REQUEST_HEADERS],
    overflow: Vec<HeaderPosition>,
}

impl HeaderPositions {
    fn new() -> Self {
        Self {
            inline: [None; INLINE_REQUEST_HEADERS],
            overflow: Vec::new(),
        }
    }

    fn push(&mut self, header: HeaderPosition) {
        if let Some(slot) = self.inline.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(header);
        } else {
            self.overflow.push(header);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = HeaderPosition> + '_ {
        self.inline
            .iter()
            .filter_map(|header| *header)
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
    let mut transfer_encodings = Vec::new();
    let mut parsed_headers = HeaderPositions::new();
    for header in request.headers.iter() {
        parsed_headers.push(HeaderPosition {
            name: byte_range(buffer, header.name.as_bytes())?,
            value: byte_range(buffer, header.value)?,
        });
        let value = std::str::from_utf8(header.value).map_err(|_| ParseError::bad_request())?;
        if header.name.eq_ignore_ascii_case("content-length") {
            let length = value
                .trim()
                .parse::<usize>()
                .map_err(|_| ParseError::bad_request())?;
            if content_length.is_some_and(|previous| previous != length) {
                return Err(ParseError::bad_request());
            }
            content_length = Some(length);
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encodings.extend(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|token| !token.is_empty())
                    .map(str::to_ascii_lowercase),
            );
        } else if header.name.eq_ignore_ascii_case("connection") {
            for token in value.split(',').map(str::trim) {
                connection_close |= token.eq_ignore_ascii_case("close");
                connection_keep_alive |= token.eq_ignore_ascii_case("keep-alive");
            }
        }
    }

    if !transfer_encodings.is_empty() && content_length.is_some() {
        return Err(ParseError::bad_request());
    }
    let body = if transfer_encodings.is_empty() {
        BodyFraming::ContentLength(content_length.unwrap_or(0))
    } else if transfer_encodings.len() == 1 && transfer_encodings[0] == "chunked" {
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
/// Returns an invalid-input error for unsafe header names/values or an
/// impossible output formatting failure.
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
    write!(output, "HTTP/1.1 {status} {}\r\n", reason_phrase(status))?;
    let mut has_date = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        if !valid_header(name, value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "response contains an invalid header",
            ));
        }
        has_date |= name.eq_ignore_ascii_case("date");
        write!(output, "{name}: {value}\r\n")?;
    }
    if let Some(length) = content_length {
        write!(output, "content-length: {length}\r\n")?;
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
        write!(output, "date: {date}\r\n")?;
    }
    if !keep_alive {
        output.extend_from_slice(b"connection: close\r\n");
    }
    output.extend_from_slice(b"\r\n");
    Ok(())
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
        write!(output, "{name}: {value}\r\n")?;
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
        write!(output, "date: {date}\r\n")?;
    }
    output.extend_from_slice(b"\r\n");
    Ok(())
}

/// Appends one HTTP/1 chunk frame to `output`.
///
/// # Errors
///
/// Returns an error if formatting the chunk length into the output buffer
/// fails.
pub fn encode_chunk(output: &mut Vec<u8>, chunk: &[u8]) -> io::Result<()> {
    write!(output, "{:X}\r\n", chunk.len())?;
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

fn valid_header(name: &str, value: &str) -> bool {
    !name.is_empty() && name.bytes().all(is_header_name_byte) && valid_header_value(value)
}

fn valid_header_value(value: &str) -> bool {
    !value
        .bytes()
        .any(|byte| byte != b'\t' && (byte < b' ' || byte == 127))
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
        BodyFraming, ChunkDecoder, Limits, Method, StreamingChunk, StreamingChunkDecoder,
        encode_response_head, encode_upgrade_response, parse_request_head,
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
