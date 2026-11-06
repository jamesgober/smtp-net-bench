//! The shared harness: every input the benches use, defined once, and one
//! function per library for each workload, so the benches and
//! `tests/equivalence.rs` run exactly the same code.
//!
//! Fairness rules (see README.md): the same inputs, a fixed Date and
//! Message-ID wherever a library lets the caller set them, the same DKIM
//! header list and canonicalization for every signer, and the same prepared
//! bytes for every SMTP client, sent to the same server over one reused
//! connection.

use std::time::{Duration, SystemTime};

pub const FROM_NAME: &str = "Example";
pub const FROM: &str = "no-reply@example.com";
pub const TO: &str = "user@example.org";
pub const SUBJECT: &str = "Confirm your email address";
pub const TEXT: &str = "Hello,\n\nPlease confirm your email address by opening this link:\nhttps://example.com/confirm/0123456789abcdef0123456789abcdef\n\nIf you did not create an account, ignore this message.\n\nThanks,\nThe Example team\n";
pub const HTML: &str = "<!doctype html><html><body><p>Hello,</p><p>Please confirm your email address by opening <a href=\"https://example.com/confirm/0123456789abcdef0123456789abcdef\">this link</a>.</p><p>If you did not create an account, ignore this message.</p><p>Thanks,<br>The Example team</p></body></html>\n";
pub const MESSAGE_ID: &str = "0123456789abcdef@example.com";
/// 2023-11-14T22:13:20Z.
pub const DATE_UNIX: u64 = 1_700_000_000;

/// The headers every DKIM signer signs, in this order, relaxed/relaxed.
pub const DKIM_HEADERS: [&str; 5] = ["From", "To", "Subject", "Date", "Message-ID"];

/// RFC 8032 section 7.1, test 1: the key of RFC 8463's DKIM example.
pub const ED25519_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
pub const ED25519_PUBLIC: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
/// Test-only RSA 2048 key (PKCS#8 and the same key as PKCS#1).
pub const RSA_PKCS8_PEM: &str = include_str!("../tests/fixtures/rsa-2048.pem");
pub const RSA_PKCS1_PEM: &str = include_str!("../tests/fixtures/rsa-2048-pkcs1.pem");

/// 1 MiB of attachment data.
pub fn attachment() -> Vec<u8> {
    (0..1u32 << 20)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect()
}

/// 1 MiB of mostly ASCII text with some accents and `=` signs, for
/// quoted-printable.
pub fn qp_text() -> String {
    "Caf\u{e9} au lait, r\u{e9}sum\u{e9}, na\u{ef}ve. Plain words mostly, with = signs.\n"
        .repeat(16_000)
}

/// A 10 KiB message for the DKIM signers, built by smtp-net.
pub fn dkim_message() -> Vec<u8> {
    let body = "Please confirm your address by opening the link below.  Thanks!\n".repeat(160);
    smtp_net::Message::builder()
        .from("Example <no-reply@example.com>")
        .unwrap()
        .to(TO)
        .unwrap()
        .subject(SUBJECT)
        .unwrap()
        .message_id(MESSAGE_ID)
        .unwrap()
        .date_unix(DATE_UNIX)
        .text(&body)
        .unwrap()
        .build()
        .unwrap()
        .to_bytes()
        .unwrap()
}

// ------------------------------------------------------------------- build

struct Fixed;
impl smtp_net::RandomSource for Fixed {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), smtp_net::Error> {
        buf.fill(7);
        Ok(())
    }
}

pub mod smtp_net_side {
    use super::*;

    pub fn verification() -> smtp_net::Message {
        smtp_net::Message::builder()
            .from("Example <no-reply@example.com>")
            .unwrap()
            .to(TO)
            .unwrap()
            .subject(SUBJECT)
            .unwrap()
            .message_id(MESSAGE_ID)
            .unwrap()
            .date_unix(DATE_UNIX)
            .text(TEXT)
            .unwrap()
            .html(HTML)
            .unwrap()
            .build_with(&mut Fixed, DATE_UNIX)
            .unwrap()
    }

    /// Build and serialize, as one step.
    pub fn verification_bytes() -> Vec<u8> {
        verification().to_bytes().unwrap()
    }

    pub fn with_attachment(data: &[u8]) -> Vec<u8> {
        smtp_net::Message::builder()
            .from(FROM)
            .unwrap()
            .to(TO)
            .unwrap()
            .message_id(MESSAGE_ID)
            .unwrap()
            .date_unix(DATE_UNIX)
            .text("see attached")
            .unwrap()
            .attachment(
                smtp_net::Attachment::new("data.bin", "application/octet-stream", data.to_vec())
                    .unwrap(),
            )
            .unwrap()
            .build_with(&mut Fixed, DATE_UNIX)
            .unwrap()
            .to_bytes()
            .unwrap()
    }

    pub fn ed25519_signer() -> smtp_net::DkimSigner {
        relaxed(
            smtp_net::DkimKey::ed25519_from_seed(&ED25519_SEED).unwrap(),
            "ed",
        )
    }

    pub fn rsa_signer() -> smtp_net::DkimSigner {
        relaxed(
            smtp_net::DkimKey::rsa_from_pem(RSA_PKCS8_PEM).unwrap(),
            "rsa",
        )
    }

    fn relaxed(key: smtp_net::DkimKey, selector: &str) -> smtp_net::DkimSigner {
        let lower: Vec<String> = DKIM_HEADERS
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        let names: Vec<&str> = lower.iter().map(String::as_str).collect();
        smtp_net::DkimSigner::new("example.com", selector, key)
            .unwrap()
            .headers(&names)
            .unwrap()
            .oversign(&[])
            .unwrap()
    }
}

pub mod lettre_side {
    use lettre::message::dkim::{
        DkimCanonicalization, DkimCanonicalizationType, DkimConfig, DkimSigningAlgorithm,
        DkimSigningKey,
    };
    use lettre::message::header::{ContentType, HeaderName};
    use lettre::message::{Attachment, Message, MultiPart, SinglePart};

    use super::*;

    fn base() -> lettre::message::MessageBuilder {
        Message::builder()
            .from(format!("{FROM_NAME} <{FROM}>").parse().unwrap())
            .to(TO.parse().unwrap())
            .message_id(Some(format!("<{MESSAGE_ID}>")))
            .date(SystemTime::UNIX_EPOCH + Duration::from_secs(DATE_UNIX))
    }

    pub fn verification() -> Message {
        base()
            .subject(SUBJECT)
            .multipart(MultiPart::alternative_plain_html(
                String::from(TEXT),
                String::from(HTML),
            ))
            .unwrap()
    }

    /// Build and serialize, as one step.
    pub fn verification_bytes() -> Vec<u8> {
        verification().formatted()
    }

    pub fn with_attachment(data: &[u8]) -> Vec<u8> {
        base()
            .multipart(
                MultiPart::mixed()
                    .singlepart(SinglePart::plain(String::from("see attached")))
                    .singlepart(Attachment::new(String::from("data.bin")).body(
                        data.to_vec(),
                        ContentType::parse("application/octet-stream").unwrap(),
                    )),
            )
            .unwrap()
            .formatted()
    }

    pub fn config(algorithm: DkimSigningAlgorithm) -> DkimConfig {
        let key = match algorithm {
            DkimSigningAlgorithm::Ed25519 => {
                use base64::Engine as _;
                DkimSigningKey::new(
                    &base64::engine::general_purpose::STANDARD.encode(ED25519_SEED),
                    algorithm,
                )
            }
            DkimSigningAlgorithm::Rsa => DkimSigningKey::new(RSA_PKCS1_PEM, algorithm),
        }
        .unwrap();
        DkimConfig::new(
            String::from("sel"),
            String::from("example.com"),
            key,
            DKIM_HEADERS
                .iter()
                .map(|h| HeaderName::new_from_ascii_str(h))
                .collect(),
            DkimCanonicalization {
                header: DkimCanonicalizationType::Relaxed,
                body: DkimCanonicalizationType::Relaxed,
            },
        )
    }

    /// lettre signs a `Message`, not bytes: the message for the DKIM bench,
    /// built by lettre with the same body.
    pub fn dkim_message() -> Message {
        let body = "Please confirm your address by opening the link below.  Thanks!\n".repeat(160);
        base()
            .subject(SUBJECT)
            .singlepart(SinglePart::plain(body))
            .unwrap()
    }
}

pub mod mail_builder_side {
    use mail_builder::MessageBuilder;
    use mail_builder::headers::address::Address;

    use super::*;

    fn base<'x>() -> MessageBuilder<'x> {
        MessageBuilder::new()
            .from(Address::new_address(Some(FROM_NAME), FROM))
            .to(TO)
            .message_id(MESSAGE_ID)
            .date(DATE_UNIX as i64)
    }

    /// Build and serialize, as one step.
    pub fn verification_bytes() -> Vec<u8> {
        base()
            .subject(SUBJECT)
            .text_body(TEXT)
            .html_body(HTML)
            .write_to_vec()
            .unwrap()
    }

    pub fn with_attachment(data: &[u8]) -> Vec<u8> {
        base()
            .text_body("see attached")
            .attachment("application/octet-stream", "data.bin", data.to_vec())
            .write_to_vec()
            .unwrap()
    }
}

pub mod mail_auth_side {
    use mail_auth::crypto::{Ed25519Key, RsaKey, Sha256};
    use mail_auth::dkim::{Canonicalization, DkimSigner};
    use mail_auth::signer::Ready;

    use super::*;

    pub fn ed25519() -> DkimSigner<Ed25519Key, Ready> {
        DkimSigner::from_key(
            Ed25519Key::from_seed_and_public_key(&ED25519_SEED, &ED25519_PUBLIC).unwrap(),
        )
        .domain("example.com")
        .selector("ed")
        .headers(DKIM_HEADERS)
        .header_canonicalization(Canonicalization::Relaxed)
        .body_canonicalization(Canonicalization::Relaxed)
    }

    #[allow(deprecated)] // from_pkcs8_pem: the PEM form keeps rustls-pki-types out of the harness
    pub fn rsa() -> DkimSigner<RsaKey<Sha256>, Ready> {
        DkimSigner::from_key(RsaKey::<Sha256>::from_pkcs8_pem(RSA_PKCS8_PEM).unwrap())
            .domain("example.com")
            .selector("rsa")
            .headers(DKIM_HEADERS)
            .header_canonicalization(Canonicalization::Relaxed)
            .body_canonicalization(Canonicalization::Relaxed)
    }
}

// -------------------------------------------------------------------- send

/// A test server for one sender: plaintext on loopback, PIPELINING and
/// CHUNKING offered (each client uses what it supports), an optional
/// simulated round trip.
pub fn server(rtt: Duration) -> smtp_net::TestServer {
    let mut b = smtp_net::TestServer::builder().extensions(&[
        "PIPELINING",
        "CHUNKING",
        "8BITMIME",
        "SIZE 10485760",
    ]);
    if !rtt.is_zero() {
        b = b.fault(smtp_net::Fault::RoundTrip(rtt));
    }
    b.start().unwrap()
}

/// The message every client sends, as bytes.
pub fn send_bytes() -> Vec<u8> {
    smtp_net_side::verification_bytes()
}

pub struct SmtpNetSender {
    client: smtp_net::Client,
    message: smtp_net::PreparedMessage,
}

impl SmtpNetSender {
    pub fn new(server: &smtp_net::TestServer) -> SmtpNetSender {
        let s = server
            .server_builder()
            .max_messages_per_connection(u32::MAX)
            .build()
            .unwrap();
        let env = smtp_net::Envelope::new(
            smtp_net::Address::parse(FROM).unwrap(),
            &[smtp_net::Address::parse(TO).unwrap()],
        )
        .unwrap();
        SmtpNetSender {
            client: smtp_net::Client::connect(&s).unwrap(),
            message: smtp_net::PreparedMessage::from_raw(env, send_bytes()).unwrap(),
        }
    }

    pub fn send(&mut self) {
        self.client.send_prepared(&self.message).unwrap();
    }
}

pub struct LettreSender {
    transport: lettre::SmtpTransport,
    envelope: lettre::address::Envelope,
    bytes: Vec<u8>,
}

impl LettreSender {
    pub fn new(server: &smtp_net::TestServer) -> LettreSender {
        // A pool of one: the connection is reused, as smtp-net's Client does.
        let transport = lettre::SmtpTransport::builder_dangerous("127.0.0.1")
            .port(server.port())
            .pool_config(lettre::transport::smtp::PoolConfig::new().max_size(1))
            .build();
        let envelope =
            lettre::address::Envelope::new(Some(FROM.parse().unwrap()), vec![TO.parse().unwrap()])
                .unwrap();
        LettreSender {
            transport,
            envelope,
            bytes: send_bytes(),
        }
    }

    pub fn send(&mut self) {
        use lettre::Transport as _;
        self.transport
            .send_raw(&self.envelope, &self.bytes)
            .unwrap();
    }
}

pub struct MailSendSender {
    runtime: tokio::runtime::Runtime,
    client: mail_send::SmtpClient<tokio::net::TcpStream>,
    bytes: Vec<u8>,
}

impl MailSendSender {
    pub fn new(server: &smtp_net::TestServer) -> MailSendSender {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let port = server.port();
        let client = runtime.block_on(async move {
            mail_send::SmtpClientBuilder::new("127.0.0.1", port)
                .unwrap()
                .implicit_tls(false)
                .connect_plain()
                .await
                .unwrap()
        });
        MailSendSender {
            runtime,
            client,
            bytes: send_bytes(),
        }
    }

    pub fn send(&mut self) {
        let message = mail_send::smtp::message::Message {
            mail_from: FROM.into(),
            rcpt_to: vec![TO.into()],
            body: std::borrow::Cow::Borrowed(&self.bytes[..]),
        };
        let client = &mut self.client;
        self.runtime
            .block_on(async move { client.send(message).await.unwrap() });
    }
}
