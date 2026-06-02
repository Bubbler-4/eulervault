use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result};
use sequoia_openpgp as openpgp;

use openpgp::crypto::{Password as OpenPgpPassword, SessionKey};
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message};
use openpgp::types::SymmetricAlgorithm;

pub(crate) fn encrypt_bytes_to_path(
    plaintext: &[u8],
    password: &str,
    destination: &Path,
) -> Result<()> {
    let mut sink = Vec::<u8>::new();
    {
        let message = Message::new(&mut sink);
        let message = Armorer::new(message).build()?;
        let message = Encryptor::with_passwords(
            message,
            std::iter::once(OpenPgpPassword::from(password.to_string())),
        )
        .symmetric_algo(SymmetricAlgorithm::AES256)
        .build()?;
        let mut literal = LiteralWriter::new(message).build()?;
        literal.write_all(plaintext)?;
        literal.finalize()?;
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(destination, sink)?;
    Ok(())
}

pub(crate) fn decrypt_bytes_from_path(source: &Path, password: &str) -> Result<Vec<u8>> {
    let ciphertext =
        fs::read(source).with_context(|| format!("failed to read {}", source.display()))?;
    let policy = StandardPolicy::new();
    let mut decryptor = DecryptorBuilder::from_bytes(&ciphertext)?.with_policy(
        &policy,
        None,
        PasswordDecryptor::new(password),
    )?;
    let mut out = Vec::new();
    decryptor.read_to_end(&mut out)?;
    Ok(out)
}

struct PasswordDecryptor {
    password: OpenPgpPassword,
}

impl PasswordDecryptor {
    fn new(password: &str) -> Self {
        Self {
            password: OpenPgpPassword::from(password.to_string()),
        }
    }
}

impl VerificationHelper for PasswordDecryptor {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for PasswordDecryptor {
    fn decrypt(
        &mut self,
        _pkesks: &[openpgp::packet::PKESK],
        skesks: &[openpgp::packet::SKESK],
        _sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        for skesk in skesks {
            if let Ok((algo, sk)) = skesk.decrypt(&self.password)
                && decrypt(algo, &sk)
            {
                return Ok(None);
            }
        }
        Err(openpgp::Error::InvalidPassword.into())
    }
}
