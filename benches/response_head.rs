//! What re-validating a response header set costs per response.
//!
//! `encode_response_head` re-checks every header name and value on every call,
//! which is right for uncontrolled input and pure waste for a header set an
//! operation sends unchanged a million times. `PreparedHeaders` pays that once.
//!
//! Measured on a noisy Windows host, two runs, medians in nanoseconds:
//!
//! | arm       | minimal | typical | heavy   |
//! |-----------|---------|---------|---------|
//! | validated | 59 / 56 | 75 / 83 | 155 / 138 |
//! | prepared  | 44 / 46 | 52 / 72 |  81 /  54 |
//! | checked   | 67 / 56 | 129 / 66 | 236 / 244 |
//!
//! `prepared` beats `validated` in every cell — the acceleration is real. The
//! conclusion is about `checked`, which is the only arm a caller can actually
//! reach: a response header set is NOT fixed per operation, because middleware
//! writes per-request values into it, so a cached block must be checked before
//! reuse. That check has to read the same bytes the validation would have, and
//! validation is already word-at-a-time (`valid_header_value` is SWAR), so
//! there is no structural headroom to win. The two runs disagree on the sign
//! for `typical`, which settles it just as well: an optimization that cannot be
//! separated from host noise is not one.
//!
//! Reaching `prepared` soundly therefore needs the bytes left untouched, not
//! compared — a per-operation head template emitted at macro expansion, where
//! the literal headers are known at compile time and only the varying tail is
//! validated. That is a different, larger piece of work; this file exists so it
//! is entered with a measurement instead of an assumption.

use blazingly_wire::{PreparedHeaders, encode_response_head, encode_response_head_prepared};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

/// A JSON operation that declares nothing: what most handlers actually send.
const MINIMAL: &[(&str, &str)] = &[("content-type", "application/json")];

/// One declared response header on top, the common shape once an operation
/// carries a location, a cache directive, or a correlation id.
const TYPICAL: &[(&str, &str)] = &[
    ("content-type", "application/json"),
    ("x-request-id", "01JQ8ZK4T7C0RXV2N9YB3M5FDA"),
];

/// A response that has been through CORS, caching, and tracing middleware.
const HEAVY: &[(&str, &str)] = &[
    ("content-type", "application/json; charset=utf-8"),
    ("x-request-id", "01JQ8ZK4T7C0RXV2N9YB3M5FDA"),
    ("access-control-allow-origin", "https://app.example.com"),
    ("cache-control", "private, max-age=0, must-revalidate"),
    ("vary", "accept-encoding, origin"),
    ("x-content-type-options", "nosniff"),
];

fn head(criterion: &mut Criterion) {
    let date = "Tue, 05 Aug 2026 12:00:00 GMT";
    let mut group = criterion.benchmark_group("response_head");

    for (label, headers) in [("minimal", MINIMAL), ("typical", TYPICAL), ("heavy", HEAVY)] {
        let prepared = PreparedHeaders::new(headers.iter().copied()).expect("headers are valid");
        // Reused across iterations exactly as the connection buffer is, so the
        // measurement is encoding work and not allocator work.
        let mut output = Vec::with_capacity(512);

        group.bench_with_input(BenchmarkId::new("validated", label), headers, |b, headers| {
            b.iter(|| {
                output.clear();
                encode_response_head(
                    black_box(&mut output),
                    black_box(200),
                    black_box(headers.iter().copied()),
                    black_box(Some(133)),
                    false,
                    true,
                    black_box(date),
                )
                .expect("encodes");
                black_box(output.len())
            });
        });

        group.bench_with_input(BenchmarkId::new("prepared", label), headers, |b, _| {
            b.iter(|| {
                output.clear();
                encode_response_head_prepared(
                    black_box(&mut output),
                    black_box(200),
                    black_box(&prepared),
                    black_box(Some(133)),
                    false,
                    true,
                    black_box(date),
                )
                .expect("encodes");
                black_box(output.len())
            });
        });

        // What a caller can actually reach. A response header set is not fixed
        // per operation — middleware writes per-request values into it: an
        // echoed CORS origin, a negotiated `content-encoding`, a
        // `content-range`. So a cached block is only sound once it has been
        // checked against this response's headers, and the check has to touch
        // the same bytes the validation would have. This arm exists to make
        // that cost visible rather than assumed.
        let snapshot = headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect::<Vec<_>>();
        let unchanged = |headers: &[(&str, &str)]| {
            headers.len() == snapshot.len()
                && headers
                    .iter()
                    .zip(&snapshot)
                    .all(|((name, value), (cached_name, cached_value))| {
                        name.eq_ignore_ascii_case(cached_name) && *value == cached_value
                    })
        };

        group.bench_with_input(BenchmarkId::new("checked", label), headers, |b, headers| {
            b.iter(|| {
                output.clear();
                if unchanged(black_box(headers)) {
                    encode_response_head_prepared(
                        black_box(&mut output),
                        black_box(200),
                        black_box(&prepared),
                        black_box(Some(133)),
                        false,
                        true,
                        black_box(date),
                    )
                    .expect("encodes");
                } else {
                    encode_response_head(
                        black_box(&mut output),
                        black_box(200),
                        black_box(headers.iter().copied()),
                        black_box(Some(133)),
                        false,
                        true,
                        black_box(date),
                    )
                    .expect("encodes");
                }
                black_box(output.len())
            });
        });
    }

    group.finish();
}

criterion_group!(benches, head);
criterion_main!(benches);
