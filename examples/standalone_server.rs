#![forbid(unsafe_code)]

use blazingly_wire::{BodyFraming, ChunkDecoder, Limits, encode_response_head, parse_request_head};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};

const READ_CHUNK: usize = 16 * 1024;

fn main() -> io::Result<()> {
    let address =
        std::env::var("BLAZINGLY_WIRE_ADDRESS").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let listener = TcpListener::bind(&address)?;
    println!("blazingly-wire standalone server listening on {address}");
    for stream in listener.incoming() {
        let stream = stream?;
        std::thread::spawn(|| {
            if let Err(error) = serve_connection(stream) {
                eprintln!("connection failed: {error}");
            }
        });
    }
    Ok(())
}

fn serve_connection(mut stream: TcpStream) -> io::Result<()> {
    let limits = Limits::new();
    let mut buffer = Vec::with_capacity(READ_CHUNK);
    let mut read_buffer = [0_u8; READ_CHUNK];
    loop {
        let head = loop {
            match parse_request_head(&buffer, limits) {
                Ok(Some(head)) => break head,
                Ok(None) => {
                    if read_more(&mut stream, &mut buffer, &mut read_buffer)? == 0 {
                        return Ok(());
                    }
                }
                Err(error) => {
                    return write_error(&mut stream, error.status, error.code, error.message);
                }
            }
        };

        let consumed = match head.body {
            BodyFraming::ContentLength(length) => {
                let total = head
                    .head_bytes
                    .checked_add(length)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "size overflow"))?;
                while buffer.len() < total {
                    if read_more(&mut stream, &mut buffer, &mut read_buffer)? == 0 {
                        return write_error(
                            &mut stream,
                            400,
                            "incomplete_body",
                            "request body ended before Content-Length",
                        );
                    }
                }
                total
            }
            BodyFraming::Chunked => {
                let mut decoder = ChunkDecoder::new(head.head_bytes, limits);
                loop {
                    match decoder.advance(&buffer) {
                        Ok(Some(body)) => break body.consumed,
                        Ok(None) => {
                            if read_more(&mut stream, &mut buffer, &mut read_buffer)? == 0 {
                                return write_error(
                                    &mut stream,
                                    400,
                                    "incomplete_body",
                                    "chunked request ended before its final chunk",
                                );
                            }
                        }
                        Err(error) => {
                            return write_error(
                                &mut stream,
                                error.status,
                                error.code,
                                error.message,
                            );
                        }
                    }
                }
            }
        };

        let body = br#"{"runtime":"blazingly-wire","status":"ok"}"#;
        let mut response = Vec::with_capacity(256);
        let date = httpdate::fmt_http_date(std::time::SystemTime::now());
        encode_response_head(
            &mut response,
            200,
            [("content-type", "application/json")],
            Some(u64::try_from(body.len()).unwrap_or(u64::MAX)),
            false,
            head.keep_alive,
            &date,
        )?;
        response.extend_from_slice(body);
        stream.write_all(&response)?;
        stream.flush()?;
        buffer.drain(..consumed);
        if !head.keep_alive {
            return Ok(());
        }
    }
}

fn read_more(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    read_buffer: &mut [u8],
) -> io::Result<usize> {
    let read = stream.read(read_buffer)?;
    buffer.extend_from_slice(&read_buffer[..read]);
    Ok(read)
}

fn write_error(stream: &mut TcpStream, status: u16, code: &str, message: &str) -> io::Result<()> {
    let body = format!(r#"{{"error":{{"code":"{code}","message":"{message}"}}}}"#);
    let date = httpdate::fmt_http_date(std::time::SystemTime::now());
    let mut response = Vec::with_capacity(body.len() + 256);
    encode_response_head(
        &mut response,
        status,
        [("content-type", "application/json")],
        Some(u64::try_from(body.len()).unwrap_or(u64::MAX)),
        false,
        false,
        &date,
    )?;
    response.extend_from_slice(body.as_bytes());
    stream.write_all(&response)
}
