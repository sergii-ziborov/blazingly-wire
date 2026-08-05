# blazingly-wire

Framework-independent HTTP/1 parsing, framing, and response encoding.

This crate owns no socket runtime. It has no async, no executor, no TLS, and no
dependency on any framework. It takes bytes you already read and tells you what
they mean; it writes bytes you then send however you like. Its only dependency
is [`httparse`].

```rust
use blazingly_wire::{BodyFraming, Limits, parse_request_head};

let bytes = b"GET /health HTTP/1.1\r\nhost: localhost\r\n\r\n";
let head = parse_request_head(bytes, Limits::new())
    .expect("well-formed request")
    .expect("complete head");
assert!(matches!(head.body, BodyFraming::ContentLength(0)));
```

## What it does

- request head parsing with explicit, enforced limits on header count, header
  bytes, body bytes, and chunk count;
- `Content-Length` and `Transfer-Encoding: chunked` body framing;
- incremental chunked decoding, including a streaming decoder that yields each
  chunk as it arrives rather than buffering the whole body;
- response head encoding, chunk encoding, and upgrade (`101`) response encoding;
- status reason phrases.

## What it does not do

- read or write sockets;
- schedule anything, or own a runtime;
- HTTP/2, TLS, routing, or application dispatch.

Those are the caller's job, which is the point: two very different callers can
share this codec.

## Two independent consumers

The design constraint is that this crate must be usable outside the framework
it was extracted from. Two consumers exercise it today:

- [Blazingly](https://github.com/sergii-ziborov/blazingly)'s native adapter,
  which is async, Compio-based, and completion-I/O driven;
- `examples/standalone_server.rs` in this repository, which is
  standard-library only, thread-per-connection, and completely synchronous.

Run the second one:

```console
cargo run --example standalone_server
curl -i http://127.0.0.1:8080/
```

`BLAZINGLY_WIRE_ADDRESS` overrides the listen address.

## Install

```toml
[dependencies]
blazingly-wire = "0.1"
```

## Status

Pre-1.0, published on crates.io. The wire behaviour is covered by unit tests
here and by fuzz targets, Miri, and AddressSanitizer jobs in the Blazingly
repository, which drives this codec against real sockets.

`unsafe_code` is forbidden.

## License

MIT. See [LICENSE](LICENSE).

[`httparse`]: https://crates.io/crates/httparse
