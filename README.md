<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>smtp-net-bench</b>
    <br>
    <sub><sup>COMPETITOR BENCHMARKS FOR SMTP-NET</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/smtp-net"><img alt="smtp-net on crates.io" src="https://img.shields.io/crates/v/smtp-net?label=smtp-net"></a>
    <a href="https://github.com/jamesgober/smtp-net-bench/actions"><img alt="CI" src="https://github.com/jamesgober/smtp-net-bench/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.98%2B-blue"></a>
</div>

<br>

<div align="left">
    <p>
        <strong>smtp-net-bench</strong> measures <a href="https://github.com/jamesgober/smtp-net">smtp-net</a> against <a href="https://crates.io/crates/lettre">lettre</a>, <a href="https://crates.io/crates/mail-builder">mail-builder</a>, <a href="https://crates.io/crates/mail-send">mail-send</a>, and <a href="https://crates.io/crates/mail-auth">mail-auth</a> on identical inputs: building and serializing messages, the transfer encoders, DKIM signing, and sending over loopback with and without simulated latency. Each comparison is reproducible from this repository alone: the competitor versions are pinned by the committed <code>Cargo.lock</code>, smtp-net comes from crates.io, and one script builds, pins, runs, and records the machine.
    </p>
    <p>
        It is a separate, unpublished repository because smtp-net must never depend on its competitors, tokio, or their dependency trees, not even as a dev-dependency of its benches. Those crates are allowed here and only here.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.98+</strong> (mail-auth's parser needs it; smtp-net itself builds on 1.85). Not published (<code>publish = false</code>). Benchmarks are never run in CI: CI builds the harness, lints it, and runs the equivalence tests.
    </p>
</div>

<hr>
<br>

## Workloads

Every input is defined once, in [`src/lib.rs`](./src/lib.rs), and the benches and the equivalence tests call the same functions.

| Id | Workload | smtp-net | Competitors | Bench |
|---|---|---|---|---|
| B1 | Build and serialize a verification email (text plus HTML, about 1 KiB); a message with a 1 MiB attachment | `MessageBuilder` then `to_bytes` | lettre `Message::builder` then `formatted`; mail-builder `MessageBuilder::write_to_vec` | [`b1_build`](./benches/b1_build.rs) |
| B2 | base64 and quoted-printable on 1 MiB | `base64_encode_lines`, `quoted_printable_encode` | the `base64` and `quoted_printable` crates (the ones lettre uses) | [`b2_encode`](./benches/b2_encode.rs) |
| B3 | DKIM Ed25519 and RSA-2048 signatures over a 10 KiB message | `DkimSigner::sign_into` | mail-auth `DkimSigner::sign` (what mail-send uses); lettre `Message::sign` | [`b3_dkim`](./benches/b3_dkim.rs) |
| B4 | 1,000 messages over one connection at 0 ms; 50 at 1 ms and 10 at 10 ms of simulated round trip | `Client::send_prepared` | lettre `SmtpTransport::send_raw` (blocking, a pool of one); mail-send `SmtpClient::send` (tokio, current-thread runtime) | [`b4_send`](./benches/b4_send.rs) |

<br>

## Fairness rules

- **Same inputs.** Every side reads the inputs from `src/lib.rs`; a bench never generates its own.
- **Same work, checked.** [`tests/equivalence.rs`](./tests/equivalence.rs) runs the functions the benches time and asserts that they agree: every built message passes smtp-net's raw-message checks (CRLF only, lines within 998 octets, a From field) and carries the same subject, addresses, Message-ID, text, and HTML; every attachment is base64 in 76-column lines from the same first line; every encoder output decodes to the input; every DKIM signer writes `relaxed/relaxed` over the same five headers with the same algorithm; every SMTP client delivers the same bytes, three times, over one connection. CI runs it on every push.
- **Fixed Date and Message-ID** wherever a library lets the caller set them, so no side pays for a clock read or a random id the others skip. smtp-net's boundary still comes from its random source (a fixed one in the harness).
- **The same server for every client.** B4 sends to smtp-net's own `TestServer` (loopback, PIPELINING and CHUNKING offered, each client uses what it supports). Its simulated round trip waits once per client-server turnaround, as a real link does, so pipelining is not charged per command. The server's own cost is in every row equally.
- **Prepared bytes.** Every client sends the same prepared message; message building is B1's job, not B4's.
- **lettre signs a `Message`.** lettre's DKIM signs its own message type in place, so its B3 row includes cloning the message; the clone alone is a separate row to subtract.
- **The base64 crate writes one unbroken line**, less work than MIME's 76-column lines; it is shown as a ceiling, not a like-for-like comparison.
- **Known differences, not hidden.** lettre and mail-send end DATA with CRLF `.` CRLF even after a message that already ends with CRLF, so the server receives one extra empty line from them; smtp-net sends the message as it is.

<br>

## Running

On Linux (in WSL, from the Linux side), with nothing else heavy running:

```bash
scripts/run.sh
```

The script pins the run to two cores (`CORES=2,3` by default: B4 runs a client and the test server), records the CPU, kernel, Rust version, load average, and the exact competitor versions, and writes `results/<date>-<commit>.md`. `scripts/run.sh --smoke` is a short run to check the harness; its file is labelled as such. `SMTP_NET_PATH=/path/to/smtp-net scripts/run.sh` measures a local checkout before a release; the results file says so.

Results are committed under [`results/`](./results/), and smtp-net's `docs/PERFORMANCE.md` cites the run it is based on.

<br>

## License

Licensed under either of the Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE)) or the MIT License ([LICENSE-MIT](./LICENSE-MIT)), at your option.
