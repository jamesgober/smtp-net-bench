//! B4: one connection, the same prepared message, sent repeatedly to
//! smtp-net's TestServer on loopback at 0, 1, and 10 ms of simulated round
//! trip (one wait per client-server turnaround).
use std::time::Duration;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use smtp_net_bench::*;

fn bench(c: &mut Criterion) {
    for (rtt_ms, count) in [(0u64, 1000usize), (1, 50), (10, 10)] {
        let rtt = Duration::from_millis(rtt_ms);
        let mut g = c.benchmark_group(format!("b4_send_{count}_rtt_{rtt_ms}ms"));
        g.sample_size(10);
        let s = server(rtt);
        let mut a = SmtpNetSender::new(&s);
        g.bench_function("smtp-net", |b| b.iter(|| (0..count).for_each(|_| a.send())));
        let s = server(rtt);
        let mut l = LettreSender::new(&s);
        g.bench_function("lettre", |b| b.iter(|| (0..count).for_each(|_| l.send())));
        let s = server(rtt);
        let mut m = MailSendSender::new(&s);
        g.bench_function("mail-send", |b| {
            b.iter(|| (0..count).for_each(|_| m.send()))
        });
        g.finish();
        black_box(());
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
