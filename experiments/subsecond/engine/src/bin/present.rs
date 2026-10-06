use anyhow::Result;
use tlsn::attestation::{Attestation, CryptoProvider, Secrets};
use kucoin_tlsn::{get_file_path, ExampleType};

fn main() -> Result<()> {
    let attestation: Attestation = bincode::deserialize(&std::fs::read(get_file_path(&ExampleType::Json, "attestation"))?)?;
    kucoin_tlsn::check_notary_key(attestation.body.verifying_key())?;
    let secrets: Secrets = bincode::deserialize(&std::fs::read(get_file_path(&ExampleType::Json, "secrets"))?)?;
    let mut proof = secrets.transcript_proof_builder();
    proof.reveal_sent(&(0..secrets.transcript().sent().len()))?;
    proof.reveal_recv(&(0..secrets.transcript().received().len()))?;
    let provider = CryptoProvider::default();
    let mut builder = attestation.presentation_builder(&provider);
    builder.identity_proof(secrets.identity_proof()).transcript_proof(proof.build()?);
    let presentation = builder.build()?;
    std::fs::write(get_file_path(&ExampleType::Json, "presentation"), bincode::serialize(&presentation)?)?;
    println!("Full request and response presentation created.");
    Ok(())
}
