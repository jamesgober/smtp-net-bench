//! A load-tolerant summary of every workload: for each row, the minimum
//! over many short batches (preemption on a busy machine only ever adds
//! time, so the minimum is the cleanest estimate of the code's own cost).
//! Prints a Markdown table; `scripts/run.sh` appends it to the results file.
//!
//! ```text
//! cargo run --release --example report
//! ```
use std::hint::black_box as bb;
use std::time::{Duration, Instant};

use lettre::message::dkim::DkimSigningAlgorithm;
use smtp_net_bench::*;

/// The minimum per-call time over `batches` batches of `per` calls.
fn min_time(batches: u32, per: u32, mut f: impl FnMut()) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..batches {
        let t = Instant::now();
        for _ in 0..per {
            f();
        }
        best = best.min(t.elapsed() / per);
    }
    best
}

fn fmt(d: Duration) -> String {
    let ns = d.as_nanos() as f64;
    if ns < 1_000.0 {
        format!("{ns:.0} ns")
    } else if ns < 1_000_000.0 {
        format!("{:.2} µs", ns / 1_000.0)
    } else {
        format!("{:.2} ms", ns / 1_000_000.0)
    }
}

fn row(workload: &str, cells: &[(&str, Duration)], bytes: Option<usize>) {
    let ours = cells[0].1;
    let mut line = format!("| {workload} |");
    for (name, d) in cells {
        let ratio = d.as_secs_f64() / ours.as_secs_f64();
        let rate = bytes
            .map(|b| format!(", {:.2} GB/s", b as f64 / d.as_secs_f64() / 1e9))
            .unwrap_or_default();
        line.push_str(&format!(" {name}: {}{rate} ({ratio:.2}x) |", fmt(*d)));
    }
    println!("{line}");
}

fn main() {
    println!("| Workload | smtp-net | others (time relative to smtp-net) |");
    println!("|---|---|---|");

    row(
        "B1 verification email, build and serialize",
        &[
            (
                "smtp-net",
                min_time(300, 50, || drop(bb(smtp_net_side::verification_bytes()))),
            ),
            (
                "lettre",
                min_time(300, 50, || drop(bb(lettre_side::verification_bytes()))),
            ),
            (
                "mail-builder",
                min_time(300, 50, || {
                    drop(bb(mail_builder_side::verification_bytes()))
                }),
            ),
        ],
        None,
    );
    let data = attachment();
    row(
        "B1 1 MiB attachment, build and serialize",
        &[
            (
                "smtp-net",
                min_time(30, 2, || drop(bb(smtp_net_side::with_attachment(&data)))),
            ),
            (
                "lettre",
                min_time(30, 2, || drop(bb(lettre_side::with_attachment(&data)))),
            ),
            (
                "mail-builder",
                min_time(30, 2, || {
                    drop(bb(mail_builder_side::with_attachment(&data)))
                }),
            ),
        ],
        Some(data.len()),
    );

    let mut out = vec![0u8; 3 << 20];
    let ours = min_time(30, 4, || {
        bb(smtp_net::base64_encode_lines(&data, &mut out).unwrap());
    });
    let theirs = min_time(30, 4, || {
        use base64::Engine as _;
        bb(base64::engine::general_purpose::STANDARD
            .encode_slice(&data, &mut out)
            .unwrap());
    });
    row(
        "B2 base64, 1 MiB",
        &[
            ("smtp-net (76-column lines)", ours),
            ("base64 crate (one line)", theirs),
        ],
        Some(data.len()),
    );
    let text = qp_text();
    let ours = min_time(30, 2, || {
        let mut st = smtp_net::QpState::new();
        let n = smtp_net::quoted_printable_encode(text.as_bytes(), &mut out, &mut st).unwrap();
        bb(n + smtp_net::quoted_printable_finish(&mut out[n..], &mut st).unwrap());
    });
    let theirs = min_time(30, 2, || {
        drop(bb(quoted_printable::encode(text.as_bytes())))
    });
    row(
        "B2 quoted-printable, 1 MiB",
        &[("smtp-net", ours), ("quoted_printable crate", theirs)],
        Some(text.len()),
    );

    let msg = dkim_message();
    let mut sig = Vec::with_capacity(1024);
    for (label, ours, algorithm) in [
        (
            "B3 DKIM Ed25519, 10 KiB",
            smtp_net_side::ed25519_signer(),
            DkimSigningAlgorithm::Ed25519,
        ),
        (
            "B3 DKIM RSA-2048, 10 KiB",
            smtp_net_side::rsa_signer(),
            DkimSigningAlgorithm::Rsa,
        ),
    ] {
        let rsa = matches!(algorithm, DkimSigningAlgorithm::Rsa);
        let (b, p) = if rsa { (40, 5) } else { (200, 20) };
        let t_ours = min_time(b, p, || {
            sig.clear();
            ours.sign_into(&msg, DATE_UNIX, &mut sig).unwrap();
        });
        let t_auth = if rsa {
            let s = mail_auth_side::rsa();
            min_time(b, p, || drop(bb(s.sign(&msg).unwrap())))
        } else {
            let s = mail_auth_side::ed25519();
            min_time(b, p, || drop(bb(s.sign(&msg).unwrap())))
        };
        let config = lettre_side::config(algorithm);
        let base = lettre_side::dkim_message();
        let t_lettre = min_time(b, p, || {
            let mut m = base.clone();
            m.sign(&config);
            bb(m);
        });
        let t_clone = min_time(b, p, || drop(bb(base.clone())));
        row(
            label,
            &[
                ("smtp-net", t_ours),
                ("mail-auth", t_auth),
                ("lettre (minus its clone)", t_lettre.saturating_sub(t_clone)),
            ],
            None,
        );
    }

    for (rtt_ms, batches, per) in [(0u64, 20u32, 100u32), (1, 3, 10), (10, 2, 3)] {
        let rtt = Duration::from_millis(rtt_ms);
        let s = server(rtt);
        let mut a = SmtpNetSender::new(&s);
        let t_ours = min_time(batches, per, || a.send());
        let s = server(rtt);
        let mut l = LettreSender::new(&s);
        let t_lettre = min_time(batches, per, || l.send());
        let s = server(rtt);
        let mut m = MailSendSender::new(&s);
        let t_send = min_time(batches, per, || m.send());
        row(
            &format!("B4 one message on a reused connection, {rtt_ms} ms round trip"),
            &[
                ("smtp-net", t_ours),
                ("lettre", t_lettre),
                ("mail-send", t_send),
            ],
            None,
        );
    }
}
