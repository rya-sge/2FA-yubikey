//extern crate yubikey;
use serde::{Serialize, Deserialize};
use crate::connection::Connection;
use crate::yubi::*;
use std::error::Error;
use strum::IntoEnumIterator;
use strum_macros::{EnumString, EnumIter};
use read_input::prelude::input;
use yubikey::{piv};
use x509::SubjectPublicKeyInfo;
use argon2::{PasswordHash, Argon2, PasswordHasher, PasswordVerifier};
use sha2::Sha256;
use hmac::{Hmac, Mac};
use crate::constante;
use sha2::Digest;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;
//mod yubi;
//use yubi::Yubi;

/// `Authenticate` enum is used to perform:
/// -   User
/// -   Registration
/// -   Password Reset
#[derive(Serialize, Deserialize, Debug, EnumString, EnumIter)]
pub enum Authenticate {
    #[strum(serialize = "Authenticate", serialize = "1")]
    Authenticate,
    #[strum(serialize = "Register", serialize = "2")]
    Register,
    #[strum(serialize = "Reset password", serialize = "3")]
    Reset,
    #[strum(serialize = "Exit", serialize = "4")]
    Exit,
}

impl Authenticate {
    pub fn display() {
        let mut actions = Authenticate::iter();
        for i in 1..=actions.len() { println!("{}.\t{:?}", i, actions.next().unwrap()); }
    }

    pub fn perform(&self, connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        connection.send(self)?;
        match self {
            Authenticate::Authenticate => Authenticate::authenticate(connection),
            Authenticate::Register => Authenticate::register(connection),
            Authenticate::Reset => Authenticate::reset_password(connection),
            Authenticate::Exit => {
                println!("Exiting...");
                std::process::exit(0);
            }
        }
    }

    fn register(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        let yubi = Yubi {};
        println!("Welcom to the register page");
        println!("Please enter the address email");
        let email = input::<String>().get();
        connection.send::<String>(&email)?;

        println!("Please enter the password");
        let password = input::<String>().get();
        connection.send::<String>(&password)?;

        println!("Please enter the Yubikey");
        let my_yubi_key = yubi.auto_yk();
        let public_key = yubi.configure_key(&mut my_yubi_key?);
        match public_key {
            Ok(v) => {
                connection.send::<Vec<u8>>(&v.public_key())?;
                println!("Public key : {:?}", v);
            }
            Err(e) => {
                connection.send::<Vec<u8>>(&vec![])?;
                println!("{:?}", e);
            }
        }
        let result = connection.receive::<String>()?;
        let success_string = constante::SUCCESS.to_string();
        if result == success_string {
            Err("Registration was successful. You must log in".into())
            //Ok(())
        } else {
            Err("Registration failed".into())
        }
    }

    fn authenticate(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        println!("Welcom to the login page");

        println!("Please enter the address email");
        let email = input::<String>().get();

        println!("Please enter the password");
        let password = input::<String>().get();

        connection.send::<String>(&email)?;

        let challenge = connection.receive::<String>()?;
        let salt = connection.receive::<String>()?;


        // Derive the key
        // Argon2 with default params (Argon2id v19)
        let argon2 = Argon2::default();

        // Hash password to PHC string ($argon2id$v=19$...)
        let password_hash = argon2.hash_password(&password.as_bytes(),
                                                 &salt).unwrap();
        let password_hash_string = password_hash.to_string();
        let parsed_hash = PasswordHash::new(&password_hash_string).unwrap();
        assert!(Argon2::default().verify_password(&password.as_bytes(), &parsed_hash).is_ok());

        // END - Derive the key
        // Compute the tag
        let str_pass = password_hash.hash.unwrap().to_string();
        let mut mac = HmacSha256::new_from_slice(&str_pass.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(challenge.as_bytes());

        let challenge_result = mac.finalize();
        let challenge_result_encode = base64::encode(challenge_result.into_bytes());
        connection.send::<String>(&challenge_result_encode)?;
        let fa_active = connection.receive::<String>()?;
        let success_string = constante::SUCCESS.to_string();
        if fa_active == success_string {
            println!("Please enter the Yubikey key");

            /********************YUbi key *******/
            let yubi = Yubi {};

            let mut my_yubi_key = yubi.auto_yk()?;

            println!("Please enter your PIN");
            let pin = input::<String>().get();
            let result_yubi_key = my_yubi_key.verify_pin(pin.as_bytes());
            match result_yubi_key {
                Ok(_val) => {}
                Err(_e) => {
                    return Err("Registration failed".into());
                }
            }
            let mut hasher = Sha256::new();
            hasher.update(&challenge);
            let challenge_sha256 = hasher.finalize().to_vec();

            let signed_buffer = piv::sign_data(
                &mut my_yubi_key,
                &challenge_sha256,
                piv::AlgorithmId::EccP256,
                piv::SlotId::Signature)?;
            let signature_encode = base64::encode(&*signed_buffer);


            connection.send::<>(&signature_encode)?;
        }

        let result = connection.receive::<String>()?;
        if result == success_string {
            Ok(())
        } else {
            Err("Authentification failed".into())
        }
    }

    fn reset_password(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        println!("Welcom to the password reset page");

        println!("Please enter the address email");
        let email = input::<String>().get();
        connection.send::<String>(&email)?;

        println!("The token has send to the email");
        println!("Please enter the token");
        let token = input::<String>().get();
        connection.send::<String>(&token)?;

        println!("Please enter the password");
        let password = input::<String>().get();
        connection.send::<String>(&password)?;
        Ok(())
    }
}
