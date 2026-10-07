use std::env;
use anyhow::{anyhow, Result};
use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use spansy::Spanned;
use tokio::{io::{AsyncRead, AsyncWrite}, sync::oneshot::{self, Receiver, Sender}};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::info;
use tlsn::{
    attestation::{request::{Request as AttestationRequest, RequestConfig}, Attestation, CryptoProvider, Secrets},
    config::{prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig, tls_commit::{mpc::MpcTlsConfig, TlsCommitConfig}},
    connection::{HandshakeData, ServerName},
    prover::{state::Committed, Prover, ProverOutput},
    transcript::TranscriptCommitConfig, webpki::RootCertStore, Session,
};
use kucoin_tlsn as tlsn_examples;
use kucoin_tlsn::{ExampleType, frame_read, frame_write};
use tlsn_formats::http::HttpTranscript;

const USER_AGENT: &str = "orakel-tlsnotary-test/0.1";
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    tokio::time::timeout(std::time::Duration::from_secs(300), run()).await??;
    Ok(())
}
async fn run() -> Result<()> {
    // One control channel, one MPC channel; both go to the peer service.
    let mut control = tokio::net::TcpStream::connect(env::var("CONTROL_ADDR").unwrap_or("127.0.0.1:7048".into())).await?;
    let socket = tokio::net::TcpStream::connect(env::var("MPC_ADDR").unwrap_or("127.0.0.1:7047".into())).await?;
    let (req_tx, req_rx) = oneshot::channel();
    let (resp_tx, resp_rx) = oneshot::channel();
    let bridge = tokio::spawn(async move {
        frame_write(&mut control, &req_rx.await?).await?;
        let response: Attestation = frame_read(&mut control).await?;
        resp_tx.send(response).map_err(|_| anyhow!("prover closed"))?;
        Ok::<(), anyhow::Error>(())
    });
    let _bridge_guard = kucoin_tlsn::AbortOnDrop::new(&bridge);
    let challenge = env::var("JOB_CHALLENGE").ok();
    if let Some(value) = &challenge { kucoin_tlsn::validate_job_challenge(value)?; }
    let headers = challenge.as_deref().map(|value| vec![("X-Oracle-Job-Challenge", value)]).unwrap_or_default();
    let (server, path) = kucoin_tlsn::api_target()?;
    kucoin_tlsn::resolve_api(&server).await?;
    prover(socket, req_tx, resp_rx, &server, &path, headers, &ExampleType::Json).await?;
    bridge.await??;
    Ok(())
}
async fn prover<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: S,
    req_tx: Sender<AttestationRequest>,
    resp_rx: Receiver<Attestation>,
    server: &str,
    uri: &str,
    extra_headers: Vec<(&str, &str)>,
    example_type: &ExampleType,
) -> Result<()> {
    // Create a session with the notary.
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();

    // Spawn the session driver to run in the background.
    let driver_task = tokio::spawn(driver);
    let _driver_guard = kucoin_tlsn::AbortOnDrop::new(&driver_task);

    // Create a new prover and perform necessary setup.
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            TlsCommitConfig::builder()
                // Select the TLS commitment protocol.
                .protocol(
                    MpcTlsConfig::builder()
                        // We must configure the amount of data we expect to exchange beforehand,
                        // which will be preprocessed prior to the
                        // connection. Reducing these limits will improve
                        // performance.
                        .max_sent_data(tlsn_examples::MAX_SENT_DATA)
                        .max_recv_data(tlsn_examples::MAX_RECV_DATA)
                        .build()?,
                )
                .build()?,
        )
        .await?;

    // Open a TCP connection to the server.
    let mut client_socket = tokio::net::TcpStream::connect(env::var("PROXY_ADDR").unwrap_or("127.0.0.1:7049".into())).await?;

    // Version 2 proxy framing precedes the end-to-end TLS stream.
    use tokio::io::AsyncWriteExt;
    if env::var("API_GENERIC").as_deref() == Ok("1") {
        client_socket.write_u16(server.len() as u16).await?;
        client_socket.write_all(server.as_bytes()).await?;
    }
    // Bind the prover to the server connection.
    let (tls_connection, prover_fut) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(server.try_into()?))
                .root_store(RootCertStore::mozilla())
                .build()?,
            client_socket.compat(),
        )
        .await?;
    let tls_connection = TokioIo::new(tls_connection.compat());

    // Spawn the prover task to be run concurrently in the background.
    let prover_task = tokio::spawn(prover_fut);
    let _prover_guard = kucoin_tlsn::AbortOnDrop::new(&prover_task);

    // Attach the hyper HTTP client to the connection.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;

    // Spawn the HTTP task to be run concurrently in the background.
    let http_task = tokio::spawn(connection);
    let _http_guard = kucoin_tlsn::AbortOnDrop::new(&http_task);

    // Build a simple HTTP request with common headers.
    let request_builder = Request::builder()
        .uri(uri)
        .header("Host", server)
        .header("Accept", "*/*")
        // Using "identity" instructs the Server not to use compression for its HTTP response.
        // TLSNotary tooling does not support compression.
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT);
    let mut request_builder = request_builder;
    for (key, value) in extra_headers {
        request_builder = request_builder.header(key, value);
    }
    let request = request_builder.body(Empty::<Bytes>::new())?;

    info!("Starting connection with the server");

    // Send the request to the server and wait for the response.
    let response = request_sender.send_request(request).await?;

    info!("Got a response from the server: {}", response.status());

    anyhow::ensure!(response.status() == StatusCode::OK, "API returned non-200");
    use http_body_util::BodyExt;
    let _body = response.into_body().collect().await?;

    // The prover task should be done now, so we can await it.
    let prover = prover_task.await??;

    // Parse the HTTP transcript.
    let transcript = HttpTranscript::parse(prover.transcript())?;

    let response = transcript.responses.first().ok_or_else(|| anyhow!("Missing HTTP response"))?;
    let body_content = &response.body.as_ref().ok_or_else(|| anyhow!("Missing HTTP response body"))?.content;
    let body = String::from_utf8_lossy(body_content.span().as_bytes());

    match body_content {
        tlsn_formats::http::BodyContent::Json(_json) => {
            let parsed = serde_json::from_str::<serde_json::Value>(&body)?;
            info!("{}", serde_json::to_string_pretty(&parsed)?);
        }
        tlsn_formats::http::BodyContent::Unknown(_span) => {
            info!("{}", &body);
        }
        _ => {}
    }

    // Commit to the transcript.
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    // This commits to various parts of the transcript separately (e.g. request
    // headers, response headers, response body and more). See https://docs.tlsnotary.org//protocol/commit_strategy.html
    // for other strategies that can be used to generate commitments.
    builder.commit_sent(&(0..prover.transcript().sent().len()))?;
    builder.commit_recv(&(0..prover.transcript().received().len()))?;

    let transcript_commit = builder.build()?;

    // Build an attestation request.
    let mut builder = RequestConfig::builder();

    builder.transcript_commit(transcript_commit);

    // Optionally, add an extension to the attestation if the notary supports it.
    // builder.extension(Extension {
    //     id: b"example.name".to_vec(),
    //     value: b"Bobert".to_vec(),
    // });

    let request_config = builder.build()?;

    let (attestation, secrets) = notarize(prover, &request_config, req_tx, resp_rx, server).await?;

    // Close the session and wait for the driver to complete.
    handle.close();
    driver_task.await??;

    // Write the attestation to disk.
    let attestation_path = tlsn_examples::get_file_path(example_type, "attestation");
    let secrets_path = tlsn_examples::get_file_path(example_type, "secrets");

    tokio::fs::write(&attestation_path, bincode::serialize(&attestation)?).await?;

    // Write the secrets to disk.
    tokio::fs::write(&secrets_path, bincode::serialize(&secrets)?).await?;

    println!("Notarization completed successfully!");
    println!(
        "The attestation has been written to `{attestation_path}` and the \
        corresponding secrets to `{secrets_path}`."
    );

    Ok(())
}

async fn notarize(
    mut prover: Prover<Committed>,
    config: &RequestConfig,
    request_tx: Sender<AttestationRequest>,
    attestation_rx: Receiver<Attestation>,
    server: &str,
) -> Result<(Attestation, Secrets)> {
    let mut builder = ProveConfig::builder(prover.transcript());

    if let Some(config) = config.transcript_commit() {
        builder.transcript_commit(config.clone());
    }

    let disclosure_config = builder.build()?;

    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&disclosure_config).await?;

    let transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;

    // Build an attestation request.
    let mut builder = AttestationRequest::builder(config);

    builder
        .server_name(ServerName::Dns(server.try_into().unwrap()))
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .expect("server cert chain is present")
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .expect("server signature is present")
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);

    let (request, secrets) = builder.build(&CryptoProvider::default())?;

    // Send attestation request to notary.
    request_tx
        .send(request.clone())
        .map_err(|_| anyhow!("notary is not receiving attestation request"))?;

    // Receive attestation from notary.
    let attestation = attestation_rx
        .await
        .map_err(|err| anyhow!("notary did not respond with attestation: {err}"))?;

    kucoin_tlsn::check_notary_key(attestation.body.verifying_key())?;

    // Signature verifier for the signature algorithm in the request.
    let provider = CryptoProvider::default();

    // Check the attestation is consistent with the Prover's view.
    request.validate(&attestation, &provider)?;

    Ok((attestation, secrets))
}
