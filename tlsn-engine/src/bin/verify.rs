use anyhow::{ensure, Context, Result};
use spansy::Spanned;
use tlsn::{attestation::{presentation::Presentation, CryptoProvider}, transcript::Transcript};
use tlsn_formats::http::HttpTranscript;
use kucoin_tlsn::{get_file_path, ExampleType, SERVER_DOMAIN, API_PATH};

fn main() -> Result<()> {
    let path = std::env::var("PRESENTATION_FILE").unwrap_or(get_file_path(&ExampleType::Json, "presentation"));
    let presentation: Presentation = bincode::deserialize(&std::fs::read(path)?)?;
    kucoin_tlsn::check_notary_key(presentation.verifying_key())?;
    let notary_public_key = hex::encode(&presentation.verifying_key().data);
    let output = presentation.verify(&CryptoProvider::default())?;
    let name = output.server_name.context("No authenticated server identity")?;
    ensure!(name.to_string() == SERVER_DOMAIN, "Unexpected API server");
    let transcript = output.transcript.context("Missing transcript")?;
    ensure!(transcript.sent_unauthed().is_empty() && transcript.received_unauthed().is_empty(), "Incomplete disclosure: all bytes must be authenticated");
    let sent = transcript.sent_unsafe();
    let received = transcript.received_unsafe();
    let http = HttpTranscript::parse(&Transcript::new(sent, received))?;
    ensure!(http.requests.len() == 1 && http.responses.len() == 1, "Expected one request and response");
    let text = std::str::from_utf8(sent)?;
    let first = text.split("\r\n").next().context("Missing request line")?;
    ensure!(first == format!("GET {API_PATH} HTTP/1.1"), "Unexpected API method or path");
    let hosts: Vec<_> = http.requests[0].headers.iter().filter(|h| h.name.as_str().eq_ignore_ascii_case("host")).collect();
    ensure!(hosts.len() == 1 && hosts[0].value.as_bytes() == SERVER_DOMAIN.as_bytes(), "Unexpected Host header");
    let challenges: Vec<_> = http.requests[0].headers.iter().filter(|h| h.name.as_str().eq_ignore_ascii_case("x-oracle-job-challenge")).collect();
    ensure!(challenges.len() <= 1, "Duplicate job challenge header");
    let job_challenge = challenges.first().map(|h| std::str::from_utf8(h.value.as_bytes())).transpose()?;
    if let Some(value) = job_challenge { kucoin_tlsn::validate_job_challenge(value)?; }
    if let Ok(expected) = std::env::var("JOB_CHALLENGE") {
        kucoin_tlsn::validate_job_challenge(&expected)?;
        ensure!(job_challenge == Some(expected.as_str()), "Missing or mismatched authenticated job challenge");
    }
    let status = std::str::from_utf8(received)?.split("\r\n").next().context("Missing status")?;
    ensure!(status.split_whitespace().nth(1) == Some("200"), "HTTP status is not 200");
    let body = http.responses[0].body.as_ref().context("No response body")?;
    let json: serde_json::Value = serde_json::from_slice(body.content.span().as_bytes())?;
    ensure!(json["code"] == "200000", "KuCoin API error");
    let price = json["data"]["price"].as_str().context("Missing price")?;
    ensure!(!price.is_empty() && price.bytes().all(|b| b.is_ascii_digit() || b == b'.'), "Invalid price format");
    let numeric: f64 = price.parse()?;
    ensure!(numeric.is_finite() && numeric > 0.0, "Invalid price");
    let time = json["data"]["time"].as_u64().context("Missing ticker timestamp")?;
    let result = serde_json::json!({
        "verified": true, "server": SERVER_DOMAIN, "path": API_PATH,
        "symbol": "KAS-USDT", "price": price, "tickerTimeMs": time,
        "tlsSessionTimeSeconds": output.connection_info.time,
        "tlsVersion": format!("{:?}", output.connection_info.version),
        "notaryPublicKey": notary_public_key,
        "jobChallenge": job_challenge,
        "requestHex": hex::encode(sent), "responseHex": hex::encode(received),
        "response": json,
    });
    std::fs::write(get_file_path(&ExampleType::Json, "verified.json"), serde_json::to_vec_pretty(&result)?)?;
    println!("VERIFIED: API identity, pinned notary key, full request and response. KAS-USDT = {price} USDT");
    Ok(())
}
