//! B1: build and serialize a verification email (text plus HTML), and a
//! message with a 1 MiB attachment.
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use smtp_net_bench::*;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("b1_verification");
    g.bench_function("smtp-net", |b| {
        b.iter(|| black_box(smtp_net_side::verification_bytes()))
    });
    g.bench_function("lettre", |b| {
        b.iter(|| black_box(lettre_side::verification_bytes()))
    });
    g.bench_function("mail-builder", |b| {
        b.iter(|| black_box(mail_builder_side::verification_bytes()))
    });
    g.finish();

    let data = attachment();
    let mut g = c.benchmark_group("b1_attachment_1mib");
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("smtp-net", |b| {
        b.iter(|| black_box(smtp_net_side::with_attachment(&data)))
    });
    g.bench_function("lettre", |b| {
        b.iter(|| black_box(lettre_side::with_attachment(&data)))
    });
    g.bench_function("mail-builder", |b| {
        b.iter(|| black_box(mail_builder_side::with_attachment(&data)))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
