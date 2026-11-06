//! B3: DKIM signatures over a 10 KiB message, relaxed/relaxed, the same
//! five headers. lettre signs a `Message` in place, so its row includes
//! cloning the message; the clone alone is measured beside it.
use criterion::{
    BenchmarkGroup, Criterion, black_box, criterion_group, criterion_main, measurement::WallTime,
};
use lettre::message::dkim::DkimSigningAlgorithm;
use smtp_net_bench::*;

fn lettre_rows(g: &mut BenchmarkGroup<'_, WallTime>, algorithm: DkimSigningAlgorithm) {
    let config = lettre_side::config(algorithm);
    let base = lettre_side::dkim_message();
    g.bench_function("lettre (with clone)", |b| {
        b.iter(|| {
            let mut m = base.clone();
            m.sign(&config);
            black_box(m)
        })
    });
    g.bench_function("lettre clone alone", |b| b.iter(|| black_box(base.clone())));
}

fn smtp_net_row(g: &mut BenchmarkGroup<'_, WallTime>, signer: &smtp_net::DkimSigner, msg: &[u8]) {
    let mut out = Vec::with_capacity(1024);
    g.bench_function("smtp-net", |b| {
        b.iter(|| {
            out.clear();
            signer
                .sign_into(black_box(msg), DATE_UNIX, &mut out)
                .unwrap();
            black_box(out.len())
        })
    });
}

fn bench(c: &mut Criterion) {
    let msg = dkim_message();

    let mut g = c.benchmark_group("b3_dkim_ed25519_10kib");
    smtp_net_row(&mut g, &smtp_net_side::ed25519_signer(), &msg);
    let s = mail_auth_side::ed25519();
    g.bench_function("mail-auth", |b| {
        b.iter(|| black_box(s.sign(black_box(&msg)).unwrap()))
    });
    lettre_rows(&mut g, DkimSigningAlgorithm::Ed25519);
    g.finish();

    let mut g = c.benchmark_group("b3_dkim_rsa2048_10kib");
    smtp_net_row(&mut g, &smtp_net_side::rsa_signer(), &msg);
    let s = mail_auth_side::rsa();
    g.bench_function("mail-auth", |b| {
        b.iter(|| black_box(s.sign(black_box(&msg)).unwrap()))
    });
    lettre_rows(&mut g, DkimSigningAlgorithm::Rsa);
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
