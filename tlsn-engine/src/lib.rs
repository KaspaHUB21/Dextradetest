use anyhow::{ensure, Result};
use serde::{de::DeserializeOwned, Serialize};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};
pub const SERVER_DOMAIN: &str = "api.kucoin.com";
pub const API_PATH: &str = "/api/v1/market/orderbook/level1?symbol=KAS-USDT";
pub const MAX_SENT_DATA: usize = 4096;
pub const MAX_RECV_DATA: usize = 16384;
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
    #[test]
    fn challenge_rejects_header_injection_and_noncanonical_hashes() {
        assert!(validate_job_challenge(&"0a".repeat(32)).is_ok());
        for value in ["", "abc", &"A".repeat(64), &"g".repeat(64), &format!("{}\r\nHost: evil", "a".repeat(64))] {
            assert!(validate_job_challenge(value).is_err());
        }
    }
}
