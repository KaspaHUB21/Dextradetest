use anyhow::{anyhow, Result};
use tokio::{io::{AsyncRead, AsyncWrite}, sync::oneshot::{self, Receiver, Sender}};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tlsn::{
    attestation::{request::Request as AttestationRequest, signing::Secp256k1Signer, Attestation, AttestationConfig, CryptoProvider},
    config::verifier::VerifierConfig,
    connection::{ConnectionInfo, TranscriptLength},
    transcript::ContentType, verifier::VerifierOutput, webpki::RootCertStore, Session,
};
use kucoin_tlsn::{frame_read, frame_write};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    if std::env::args().nth(1).as_deref() == Some("init") {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let mut secret = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open("notary.key")?;
        secret.write_all(&key.to_bytes())?;
        let public = hex::encode(key.verifying_key().to_sec1_bytes());
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open("notary.pub")?;
        writeln!(file, "{public}")?;
        println!("Notary keys created; public key must be trusted separately.");
        return Ok(());
    }
    anyhow::ensure!(std::path::Path::new("notary.key").exists(), "Run notary init first");
    // Loopback-only test service. No unauthenticated public deployment.
    let base: u16 = std::env::var("NOTARY_BASE_PORT").unwrap_or("7047".into()).parse()?;
    anyhow::ensure!(base > 1024 && base < 65533, "Invalid local notary port");
    let mpc = tokio::net::TcpListener::bind(("127.0.0.1", base)).await?;
    let control = tokio::net::TcpListener::bind(("127.0.0.1", base + 1)).await?;
    let proxy = tokio::net::TcpListener::bind(("127.0.0.1", base + 2)).await?;
    let proxy_slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let proxy_task = tokio::spawn(async move {
        loop {
            let (mut client, _) = proxy.accept().await?;
            let Ok(permit) = proxy_slots.clone().try_acquire_owned() else { continue; };
            tokio::spawn(async move {
                let _permit = permit;
                let result = tokio::time::timeout(std::time::Duration::from_secs(300), async {
                    use tokio::io::AsyncReadExt;
                    let mut first = [0u8; 1];
                    anyhow::ensure!(client.peek(&mut first).await? == 1, "Empty API proxy connection");
                    let server = if first[0] == 0x16 {
                        kucoin_tlsn::SERVER_DOMAIN.to_string()
                    } else {
                    anyhow::ensure!(first[0] == 0, "Unsupported proxy protocol");
                    let len = client.read_u16().await? as usize;
                    anyhow::ensure!(len > 0 && len <= 253, "Invalid API target frame");
                    let mut name = vec![0; len]; client.read_exact(&mut name).await?;
                    std::str::from_utf8(&name)?.to_owned()
                    };
                    let mut addresses = kucoin_tlsn::resolve_api(&server).await?;
                    addresses.sort_by_key(|address| if address.is_ipv4() { 0 } else { 1 });
                    let mut api = tokio::net::TcpStream::connect(addresses.as_slice()).await?;
                    kucoin_tlsn::bounded_api_proxy(&mut client, &mut api).await?;
                    Ok::<(), anyhow::Error>(())
                }).await;
                if !matches!(result, Ok(Ok(()))) { eprintln!("API forwarding failed: {result:?}"); }
            });
        }
        #[allow(unreachable_code)] Ok::<(), anyhow::Error>(())
    });
    let _proxy_guard = kucoin_tlsn::AbortOnDrop::new(&proxy_task);
    println!("Local MPC notary and public HTTPS443 forwarding service ready (proxy framing v2).");
    loop {
        let (mut ctl, _) = control.accept().await?;
        let session = async {
            let (socket, _) = mpc.accept().await?;
            let (req_tx, req_rx) = oneshot::channel();
            let (resp_tx, resp_rx) = oneshot::channel();
            let bridge = tokio::spawn(async move {
                let request: AttestationRequest = frame_read(&mut ctl).await?;
                req_tx.send(request).map_err(|_| anyhow!("notary closed"))?;
                frame_write(&mut ctl, &resp_rx.await?).await?;
                Ok::<(), anyhow::Error>(())
            });
            let _bridge_guard = kucoin_tlsn::AbortOnDrop::new(&bridge);
            let result = notary(socket, req_rx, resp_tx).await;
            if result.is_err() { bridge.abort(); }
            result?;
            bridge.await??;
            Ok::<(), anyhow::Error>(())
        };
        match tokio::time::timeout(std::time::Duration::from_secs(300), session).await {
            Ok(Ok(())) => println!("Session attested."),
            result => eprintln!("Session failed: {result:?}"),
        }
    }
}
async fn notary<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: S,
    request_rx: Receiver<AttestationRequest>,
    attestation_tx: Sender<Attestation>,
) -> Result<()> {
    // Create a session with the prover.
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();

    // Spawn the session driver to run in the background.
    let driver_task = tokio::spawn(driver);
    let _driver_guard = kucoin_tlsn::AbortOnDrop::new(&driver_task);

    let verifier_config = VerifierConfig::builder().root_store(RootCertStore::mozilla()).build()?;

    let pending = handle
        .new_verifier(verifier_config)?
        .commit()
        .await?;
    // Reject hostile resource proposals before MPC preprocessing allocates.
    let tlsn::config::tls_commit::TlsCommitProtocolConfig::Mpc(config) = pending.request().protocol() else {
        pending.reject(Some("Only MPC TLS is supported")).await?;
        return Err(anyhow!("Unsupported TLS commitment protocol"));
    };
    let within_limits = config.max_sent_data() <= kucoin_tlsn::MAX_SENT_DATA
        && config.max_recv_data() <= kucoin_tlsn::MAX_RECV_DATA
        && config.max_recv_data_online() <= kucoin_tlsn::MAX_RECV_DATA
        && config.max_sent_records().is_none_or(|limit| limit <= 256)
        && config.max_recv_records_online().is_none_or(|limit| limit <= 256);
    if !within_limits {
        pending.reject(Some("TLS resource limits exceeded")).await?;
        return Err(anyhow!("TLS resource limits exceeded"));
    }
    let verifier = pending.accept()
        .await?
        .run()
        .await?;

    let (
        VerifierOutput {
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier.verify().await?.accept().await?;

    let tls_transcript = verifier.tls_transcript().clone();

    verifier.close().await?;

    let sent_len = tls_transcript
        .sent()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();

    let recv_len = tls_transcript
        .recv()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();

    // Receive attestation request from prover.
    let request = request_rx.await?;

    // Load a dummy signing key.
    let signing_key = k256::ecdsa::SigningKey::from_slice(&std::fs::read("notary.key")?)?;
    let signer = Box::new(Secp256k1Signer::new(&signing_key.to_bytes())?);
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);

    // Build an attestation.
    let mut att_config_builder = AttestationConfig::builder();
    att_config_builder.supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    let att_config = att_config_builder.build()?;

    let mut builder = Attestation::builder(&att_config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: (*tls_transcript.version()),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(tls_transcript.server_ephemeral_key().clone())
        .transcript_commitments(transcript_commitments);

    let attestation = builder.build(&provider)?;

    // Send attestation to prover.
    attestation_tx
        .send(attestation)
        .map_err(|_| anyhow!("prover is not receiving attestation"))?;

    // Close the session and wait for the driver to complete.
    handle.close();
    driver_task.await??;

    Ok(())
}
