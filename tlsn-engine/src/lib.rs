#[cfg(tlsn_insecure)]
compile_error!("Insecure TLSNotary builds are forbidden for oracle attestations");
use anyhow::{ensure, Result};
use serde::{de::DeserializeOwned, Serialize};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};
pub const SERVER_DOMAIN: &str = "api.kucoin.com";
pub const API_PATH: &str = "/api/v1/market/orderbook/level1?symbol=KAS-USDT";
pub const MAX_SENT_DATA: usize = 4096;
pub const MAX_RECV_DATA: usize = 16384;
pub async fn bounded_api_proxy(client: &mut TcpStream, api: &mut TcpStream) -> Result<()> {
    // Also bound a hostile peer that opens the proxy without a valid MPC session.
    // TLS handshake/certificate overhead is separate from plaintext transcript.
    const LIMIT: u64 = 128 * 1024;
    let (client_read, mut client_write) = client.split();
    let (api_read, mut api_write) = api.split();
    let up = async {
        let count = tokio::io::copy(&mut client_read.take(LIMIT + 1), &mut api_write).await?;
        ensure!(count <= LIMIT, "API proxy upload exceeds transport limit");
        api_write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };
    let down = async {
        let count = tokio::io::copy(&mut api_read.take(LIMIT + 1), &mut client_write).await?;
        ensure!(count <= LIMIT, "API proxy download exceeds transport limit");
        client_write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };
    tokio::try_join!(up, down)?;
    Ok(())
}
pub fn api_target() -> Result<(String, String)> {
    let server = std::env::var("API_SERVER").unwrap_or(SERVER_DOMAIN.into());
    validate_api_server(&server)?;
    let path = std::env::var("API_PATH").unwrap_or(API_PATH.into());
    ensure!(path.starts_with('/') && !path.starts_with("//") && path.len() <= 1024 && path.bytes().all(|b| (33..=126).contains(&b) && b != b'#' && b != b'\\'), "Invalid API path");
    Ok((server, path))
}
pub fn validate_api_server(server: &str) -> Result<()> {
    let labels: Vec<_> = server.split('.').collect();
    ensure!(server.len() <= 253 && labels.len() >= 2 && labels.iter().all(|label| !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-') && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')), "Invalid public API hostname");
    let suffix = labels.last().unwrap();
    ensure!(suffix.len() >= 2 && suffix.bytes().all(|b| b.is_ascii_lowercase()) && !["localhost", "local", "internal", "test", "invalid", "example", "onion"].contains(suffix), "Invalid public API hostname");
    Ok(())
}
pub fn public_api_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let value = u32::from(v4);
            ![(0x00000000,8), (0x0a000000,8), (0x64400000,10), (0x7f000000,8), (0xa9fe0000,16), (0xac100000,12), (0xc0000000,24), (0xc0000200,24), (0xc0586300,24), (0xc0a80000,16), (0xc6120000,15), (0xc6336400,24), (0xcb007100,24), (0xe0000000,4), (0xf0000000,4)].iter().any(|&(base,prefix)| value >> (32-prefix) == base >> (32-prefix))
        },
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() { return public_api_ip(v4.into()); }
            let value = u128::from(v6);
            // Conservatively permit global-unicast only, excluding special-use
            // 2001::/23, documentation, 6to4 and future documentation blocks.
            value >> 125 == 1 && ![(0x20010000000000000000000000000000u128,23), (0x20010db8000000000000000000000000,32), (0x20020000000000000000000000000000,16), (0x3fff0000000000000000000000000000,20)].iter().any(|&(base,prefix)| value >> (128-prefix) == base >> (128-prefix))
        }
    }
}
pub async fn resolve_api(server: &str) -> Result<Vec<std::net::SocketAddr>> {
    validate_api_server(server)?;
    let addresses: Vec<_> = tokio::time::timeout(std::time::Duration::from_secs(10), tokio::net::lookup_host((server,443))).await??.collect();
    ensure!(!addresses.is_empty() && addresses.len() <= 16 && addresses.iter().all(|a| public_api_ip(a.ip())), "API DNS returned a disallowed address");
    Ok(addresses)
}
// Detached Tokio tasks must not survive a failed/timed-out session.
pub struct AbortOnDrop(tokio::task::AbortHandle);
impl AbortOnDrop {
    pub fn new<T>(task: &tokio::task::JoinHandle<T>) -> Self { Self(task.abort_handle()) }
}
impl Drop for AbortOnDrop { fn drop(&mut self) { self.0.abort(); } }
pub fn validate_job_challenge(value: &str) -> Result<()> {
    ensure!(value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "Invalid job challenge: expected 64 lowercase hexadecimal characters");
    Ok(())
}
#[derive(clap::ValueEnum, Clone, Default, Debug)]
pub enum ExampleType { #[default] Json, Html, Authenticated }
impl std::fmt::Display for ExampleType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { write!(f, "{self:?}") }
}
pub fn get_file_path(_: &ExampleType, kind: &str) -> String {
    let dir = std::env::var("OUTPUT_DIR").unwrap_or(".".into());
    format!("{dir}/kucoin.{kind}.tlsn")
}
pub fn check_notary_key(key: &tlsn::attestation::signing::VerifyingKey) -> Result<()> {
    let file = std::env::var("TRUSTED_NOTARY_KEY").unwrap_or("notary.pub".into());
    let expected = hex::decode(std::fs::read_to_string(file)?.trim())?;
    let expected = k256::ecdsa::VerifyingKey::from_sec1_bytes(&expected)?;
    let actual = k256::ecdsa::VerifyingKey::from_sec1_bytes(&key.data)?;
    ensure!(expected == actual, "Untrusted notary key");
    Ok(())
}
pub async fn frame_write<T: Serialize>(stream: &mut TcpStream, value: &T) -> Result<()> {
    let data = bincode::serialize(value)?;
    ensure!(data.len() <= 8 * 1024 * 1024, "Control frame too large");
    stream.write_u32(data.len() as u32).await?;
    stream.write_all(&data).await?;
    Ok(())
}
pub async fn frame_read<T: DeserializeOwned>(stream: &mut TcpStream) -> Result<T> {
    let len = stream.read_u32().await? as usize;
    ensure!(len <= 8 * 1024 * 1024, "Control frame too large");
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).await?;
    Ok(bincode::deserialize(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::validate_job_challenge;
    #[tokio::test]
    async fn proxy_rejects_excess_transport_bytes_without_mpc() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let clients = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let apis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client_peer = tokio::net::TcpStream::connect(clients.local_addr().unwrap()).await.unwrap();
        let (mut proxy_client, _) = clients.accept().await.unwrap();
        let mut api_peer = tokio::net::TcpStream::connect(apis.local_addr().unwrap()).await.unwrap();
        let (mut proxy_api, _) = apis.accept().await.unwrap();
        client_peer.shutdown().await.unwrap();
        let reader = tokio::spawn(async move { let mut out = Vec::new(); let _ = client_peer.read_to_end(&mut out).await; });
        let writer = tokio::spawn(async move { api_peer.write_all(&vec![0u8; 128 * 1024 + 1]).await.unwrap(); api_peer.shutdown().await.unwrap(); });
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), super::bounded_api_proxy(&mut proxy_client, &mut proxy_api)).await.unwrap();
        assert!(result.unwrap_err().to_string().contains("transport limit"));
        drop(proxy_client); drop(proxy_api); writer.await.unwrap(); reader.await.unwrap();
    }
    #[test]
    fn api_ssrf_special_ranges_and_mapped_addresses() {
        for ip in ["0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.0.0.9", "192.0.2.1", "192.88.99.1", "192.168.1.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255", "::1", "::", "::ffff:127.0.0.1", "::ffff:192.168.1.1", "fc00::1", "fe80::1", "ff02::1", "64:ff9b::a00:1", "2001::1", "2001:db8::1", "2002::1", "3fff::1"] {
            assert!(!super::public_api_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "8.8.8.8", "100.63.255.255", "100.128.0.1", "172.15.255.255", "172.32.0.1", "223.255.255.255", "::ffff:8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888", "2001:200::1"] {
            assert!(super::public_api_ip(ip.parse().unwrap()), "{ip}");
        }
        for name in ["localhost", "127.0.0.1", "api.local", "api.invalid", "user@evil.com", "evil.com:443", "evil.com\r\nHost:x"] { assert!(super::validate_api_server(name).is_err()); }
        assert!(super::validate_api_server("api.kucoin.com").is_ok());
    }
    #[test]
    fn challenge_rejects_header_injection_and_noncanonical_hashes() {
        assert!(validate_job_challenge(&"0a".repeat(32)).is_ok());
        for value in ["", "abc", &"A".repeat(64), &"g".repeat(64), &format!("{}\r\nHost: evil", "a".repeat(64))] {
            assert!(validate_job_challenge(value).is_err());
        }
    }
}
