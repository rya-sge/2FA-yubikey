use std::io;
use std::io::Read;
use yubikey::*;
use yubikey::YubiKey;
use yubikey::piv::{AlgorithmId, SlotId};
use yubikey::certificate::PublicKeyInfo;

pub struct Yubi;

impl Yubi {
    pub(crate) fn auto_yk(&self) -> Result<YubiKey> {
        loop {
            for reader in Context::open()?.iter()? {
                if let Ok(yk) = reader.open() {
                    println!("Yubikey detected");
                    return Ok(yk);
                }
            }

            println!("No Yubikey detected: Please enter one and press [Enter] to continue...");
            let _ = io::stdin().read(&mut [0u8]).unwrap();
        }
    }
    pub(crate) fn configure_key(&self, yubi: &mut YubiKey) -> Result<PublicKeyInfo> {
        yubi.authenticate(MgmKey::default()).unwrap();
        let public_key = yubikey::piv::generate(yubi, SlotId::Signature, AlgorithmId::EccP256,
                                                PinPolicy::Default, TouchPolicy::Never);
        yubi.verify_pin("123456".as_bytes())?;
        return public_key;
    }
}
