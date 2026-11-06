//! The benches time these exact functions; this file proves the libraries
//! do the same work on the same inputs. CI runs it on every push.

use std::time::Duration;

use mail_auth::headers::HeaderWriter as _;
use smtp_net_bench::*;

/// Every message must pass smtp-net's raw-input checks (CRLF only, lines
/// within 998 octets, a header block, a From field).
fn well_formed(bytes: &[u8]) {
    let env = smtp_net::Envelope::new(
        smtp_net::Address::parse(FROM).unwrap(),
        &[smtp_net::Address::parse(TO).unwrap()],
    )
    .unwrap();
    smtp_net::PreparedMessage::from_raw(env, bytes.to_vec()).unwrap();
}

fn text(bytes: &[u8]) -> String {
    // Undo quoted-printable soft breaks so phrases can be found in any encoding.
    String::from_utf8_lossy(bytes).replace("=\r\n", "")
}

#[test]
fn b1_every_builder_writes_the_same_message() {
    for (name, bytes) in [
        ("smtp-net", smtp_net_side::verification_bytes()),
        ("lettre", lettre_side::verification_bytes()),
        ("mail-builder", mail_builder_side::verification_bytes()),
    ] {
        well_formed(&bytes);
        let t = text(&bytes);
        let lower = t.to_ascii_lowercase();
        assert!(lower.contains("multipart/alternative"), "{name}");
        assert!(
            lower.contains("text/plain") && lower.contains("text/html"),
            "{name}"
        );
        assert!(t.contains(SUBJECT), "{name}");
        assert!(t.contains(FROM) && t.contains(TO), "{name}");
        assert!(t.contains(MESSAGE_ID), "{name}");
        // The link in the text part and in the HTML part.
        assert!(t.matches("confirm/0123456789abcdef").count() >= 2, "{name}");
        assert!(t.contains("this link"), "{name}");
    }
}

#[test]
fn b1_every_builder_writes_the_same_attachment() {
    let data = attachment();
    let mut first_line = [0u8; 80];
    let n = smtp_net::base64_encode_lines(&data[..57], &mut first_line).unwrap();
    let first_line = std::str::from_utf8(&first_line[..n]).unwrap().to_owned();
    for (name, bytes) in [
        ("smtp-net", smtp_net_side::with_attachment(&data)),
        ("lettre", lettre_side::with_attachment(&data)),
        ("mail-builder", mail_builder_side::with_attachment(&data)),
    ] {
        well_formed(&bytes);
        let t = String::from_utf8_lossy(&bytes);
        assert!(
            t.contains(&first_line),
            "{name}: base64 of the data, 76-column lines"
        );
        assert!(t.contains("data.bin"), "{name}");
        // About 4/3 of the data plus line breaks and headers.
        let ratio = bytes.len() as f64 / data.len() as f64;
        assert!((1.33..1.40).contains(&ratio), "{name}: {ratio}");
    }
}

#[test]
fn b2_encoders_round_trip() {
    use base64::Engine as _;
    let data = attachment();
    let mut out = vec![0u8; 3 << 20];
    let n = smtp_net::base64_encode_lines(&data, &mut out).unwrap();
    let joined: Vec<u8> = out[..n]
        .iter()
        .copied()
        .filter(|&b| b != b'\r' && b != b'\n')
        .collect();
    assert_eq!(
        joined,
        base64::engine::general_purpose::STANDARD
            .encode(&data)
            .into_bytes()
    );

    let qp = qp_text();
    let mut st = smtp_net::QpState::new();
    let k = smtp_net::quoted_printable_encode(qp.as_bytes(), &mut out, &mut st).unwrap();
    let k = k + smtp_net::quoted_printable_finish(&mut out[k..], &mut st).unwrap();
    let decoded = quoted_printable::decode(&out[..k], quoted_printable::ParseMode::Strict).unwrap();
    assert_eq!(
        String::from_utf8(decoded).unwrap().replace("\r\n", "\n"),
        qp
    );
    let reference = quoted_printable::encode(qp.as_bytes());
    let reference =
        quoted_printable::decode(&reference, quoted_printable::ParseMode::Strict).unwrap();
    assert_eq!(
        String::from_utf8(reference).unwrap().replace("\r\n", "\n"),
        qp
    );
}

/// The tags of a DKIM-Signature header, whitespace removed.
fn tags(header: &str) -> Vec<(String, String)> {
    let value = header.split_once(':').unwrap().1;
    let flat: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    flat.split(';')
        .filter(|t| !t.is_empty())
        .map(|t| {
            let (k, v) = t.split_once('=').unwrap();
            (k.to_owned(), v.to_owned())
        })
        .collect()
}

fn check_signature(name: &str, header: &str, algorithm: &str) {
    let t = tags(header);
    let get = |k: &str| {
        t.iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    };
    assert_eq!(get("a"), algorithm, "{name}");
    assert_eq!(get("c"), "relaxed/relaxed", "{name}");
    assert_eq!(get("d"), "example.com", "{name}");
    // The same set of headers (mail-auth lists them in its own order).
    let mut h: Vec<String> = get("h")
        .split(':')
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let mut want: Vec<String> = DKIM_HEADERS
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    h.sort();
    want.sort();
    assert_eq!(h, want, "{name}: the same headers signed");
    assert!(get("b").len() > 40 && !get("bh").is_empty(), "{name}");
}

#[test]
fn b3_every_signer_signs_the_same_way() {
    let msg = dkim_message();
    check_signature(
        "smtp-net ed25519",
        &smtp_net_side::ed25519_signer()
            .sign(&msg, DATE_UNIX)
            .unwrap(),
        "ed25519-sha256",
    );
    check_signature(
        "smtp-net rsa",
        &smtp_net_side::rsa_signer().sign(&msg, DATE_UNIX).unwrap(),
        "rsa-sha256",
    );
    check_signature(
        "mail-auth ed25519",
        &mail_auth_side::ed25519().sign(&msg).unwrap().to_header(),
        "ed25519-sha256",
    );
    check_signature(
        "mail-auth rsa",
        &mail_auth_side::rsa().sign(&msg).unwrap().to_header(),
        "rsa-sha256",
    );
    for (alg, want) in [
        (
            lettre::message::dkim::DkimSigningAlgorithm::Ed25519,
            "ed25519-sha256",
        ),
        (
            lettre::message::dkim::DkimSigningAlgorithm::Rsa,
            "rsa-sha256",
        ),
    ] {
        let mut m = lettre_side::dkim_message();
        m.sign(&lettre_side::config(alg));
        let f = String::from_utf8(m.formatted()).unwrap();
        let start = f.find("DKIM-Signature:").unwrap();
        let rest = &f[start..];
        let mut end = 0;
        for (i, _) in rest.match_indices("\r\n") {
            if !rest[i + 2..].starts_with([' ', '\t']) {
                end = i;
                break;
            }
        }
        check_signature("lettre", &rest[..end], want);
    }
}

#[test]
fn b4_every_client_delivers_the_same_bytes() {
    let want = send_bytes();
    let check = |server: &smtp_net::TestServer, name: &str| {
        let got = server.received();
        assert_eq!(got.len(), 3, "{name}");
        for m in &got {
            // lettre and mail-send end DATA with CRLF "." CRLF even after a final CRLF, so
            // their messages arrive with one more empty line.
            let same = m.data == want
                || (name != "smtp-net" && m.data.strip_suffix(b"\r\n") == Some(&want[..]));
            assert!(
                same,
                "{name}: {} octets received, {} sent",
                m.data.len(),
                want.len()
            );
            assert_eq!(m.recipients, [TO], "{name}");
        }
        assert_eq!(server.connections(), 1, "{name}: one reused connection");
    };
    let s = server(Duration::ZERO);
    let mut a = SmtpNetSender::new(&s);
    for _ in 0..3 {
        a.send();
    }
    check(&s, "smtp-net");
    let s = server(Duration::ZERO);
    let mut b = LettreSender::new(&s);
    for _ in 0..3 {
        b.send();
    }
    check(&s, "lettre");
    let s = server(Duration::ZERO);
    let mut c = MailSendSender::new(&s);
    for _ in 0..3 {
        c.send();
    }
    check(&s, "mail-send");
}
