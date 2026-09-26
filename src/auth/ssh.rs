use crate::{Error, Result};
use ssh_key::{Algorithm, PublicKey, SshSig};
pub const NAMESPACE: &str = "patchwork-auth-v1";
pub fn public_key(encoded: &str) -> Result<PublicKey> {
    if encoded.len() > 1024 {
        return Err(Error::Invalid("SSH public key"));
    }
    let key = PublicKey::from_openssh(encoded).map_err(|_| Error::Invalid("SSH public key"))?;
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(Error::Invalid("Ed25519 public key"));
    }
    Ok(key)
}
pub fn verify(key: &PublicKey, payload: &[u8], signature: &str) -> Result<()> {
    if signature.len() > 4096 {
        return Err(Error::Unauthorized);
    }
    let signature = SshSig::from_pem(signature).map_err(|_| Error::Unauthorized)?;
    key.verify(NAMESPACE, payload, &signature)
        .map_err(|_| Error::Unauthorized)
}
