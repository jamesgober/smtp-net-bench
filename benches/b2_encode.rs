//! B2: the transfer encoders on 1 MiB. The references are the crates lettre
//! uses (`base64`, `quoted_printable`); `base64` writes one unbroken line,
//! less work than MIME's 76-column lines, and is shown as a ceiling.
use base64::Engine as _;
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use smtp_net_bench::*;

fn bench(c: &mut Criterion) {
    let data = attachment();
    let mut out = vec![0u8; 3 << 20];
    let mut g = c.benchmark_group("b2_base64_1mib");
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("smtp-net (76-column lines)", |b| {
        b.iter(|| black_box(smtp_net::base64_encode_lines(&data, &mut out).unwrap()))
    });
    g.bench_function("base64 crate (one line)", |b| {
        b.iter(|| {
            black_box(
                base64::engine::general_purpose::STANDARD
                    .encode_slice(&data, &mut out)
                    .unwrap(),
            )
        })
    });
    g.finish();

    let text = qp_text();
    let mut g = c.benchmark_group("b2_quoted_printable_1mib");
    g.throughput(Throughput::Bytes(text.len() as u64));
    g.bench_function("smtp-net", |b| {
        b.iter(|| {
            let mut st = smtp_net::QpState::new();
            let n = smtp_net::quoted_printable_encode(text.as_bytes(), &mut out, &mut st).unwrap();
            black_box(n + smtp_net::quoted_printable_finish(&mut out[n..], &mut st).unwrap())
        })
    });
    g.bench_function("quoted_printable crate", |b| {
        b.iter(|| black_box(quoted_printable::encode(text.as_bytes())))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
