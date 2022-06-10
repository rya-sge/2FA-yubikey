use serde::{Serialize, Deserialize};
use crate::connection::Connection;
use std::error::Error;
use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{Argon2, PasswordHash, PasswordVerifier, PasswordHasher};
use crate::database::Database;
use crate::mailer::send_mail;
use sodiumoxide::crypto::secretbox;
use sha2::Sha256;
use p256;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::VerifyingKey;
use p256::EncodedPoint;
// A trait that the Validate derive will impl
use validator::{validate_email};

use hmac::{Hmac, Mac};
use crate::constante::SUCCESS;
use crate::constante::FAIL;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

//use std::alloc::Global;
/// `Authenticate` enum is used to perform:
/// -   Authentication
/// -   Registration
/// -   Password Reset
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum Authenticate {
    Authenticate,
    Register,
    Reset,
    Exit,
}


fn add_user(email: &String, password: &String, public_key: &Vec<u8>) -> User {
    let salt_password_hash = SaltString::generate(&mut OsRng);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = argon2.hash_password(&password.as_bytes(),
                                             &salt_password_hash).unwrap();
    let password_hash_string = password_hash.to_string();
    let parsed_hash = PasswordHash::new(&password_hash_string).unwrap();
    assert!(Argon2::default().verify_password(&password.as_bytes(), &parsed_hash).is_ok());

    let user = User {
        email: email.clone(),
        password: password_hash.hash.unwrap().to_string(),
        salt: salt_password_hash.as_str().to_string(),
        public_key: public_key.clone(),
        fa_2: true,
    };
    Database::insert(&user).unwrap();
    return user;
}

impl Authenticate {
    pub fn perform(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        match connection.receive()? {
            Authenticate::Authenticate => Authenticate::authenticate(connection),
            Authenticate::Register => Authenticate::register(connection),
            Authenticate::Reset => Authenticate::reset_password(connection),
            Authenticate::Exit => Err("Client disconnected")?
        }
    }


    fn register(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        let email = connection.receive::<String>()?;
        if !validate_email(&email) {
            println!("Email invalide");
            return Err("Email invalid".into());
        } else {
            let password = connection.receive::<String>()?;
            let public_key = connection.receive::<Vec<u8>>()?;
            println!("public_key {:?}", public_key);
            let search_user = Database::get(&email);
            match search_user {
                Ok(val) => {
                    match val {
                        Some(_val) => {
                            println!("The user already exists");
                            connection.send::<String>(&FAIL.to_string())?;
                            return Err("The user already exists".into());
                        }
                        None => {
                            let result = add_user(&email, &password, &public_key);
                            connection.send::<String>(&SUCCESS.to_string())?;
                            return Ok(Some(result));
                        }
                    }
                }
                Err(e) => {
                    connection.send::<String>(&FAIL.to_string())?;
                    return Err(e);
                }
            }
        }
    }

    fn reset_password(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        let email = connection.receive::<String>()?;
        if !validate_email(&email) {
            println!("Email invalide");
            return Err("Email invalid".into());
        }
        let nonce = secretbox::gen_nonce();
        let nonce_encode = base64::encode(nonce);
        let search_user = Database::get(&email);
        match search_user{
            Ok(user_option)=>{
               match user_option {
                    Some(user) =>{
                        send_mail(&email.to_string(), &"Password reset".to_string(), &nonce_encode);
                        let token_receive = connection.receive::<String>()?;
                        if token_receive == nonce_encode {
                            let password = connection.receive::<String>()?;
                            add_user(&email, &password, &user.public_key);
                        }
                    }

                   _ => {
                       let token_receive = connection.receive::<String>()?;
                       // Protection against timing attack
                       if token_receive == nonce_encode {
                           let _password = connection.receive::<String>()?;
                       }
                   }
               }
            }
            _ => {
                let token_receive = connection.receive::<String>()?;
                // Protection against timing attack
                if token_receive == nonce_encode {
                    let _password = connection.receive::<String>()?;
                }
            }
        }
        Ok(None)
    }

    fn authenticate(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        let email = connection.receive::<String>()?;
        let search_user = Database::get(&email);

        //waring from compiler but it's normal
        let mut user_exist = false;
        let fake_salt = SaltString::generate(&mut OsRng);

        //Timing attack protection
        let mut user = User {
            email,
            password: "incredible".to_string(),
            salt: fake_salt.as_str().to_string(),
            public_key: vec![],
            fa_2: true,
        };
        //search user in the database
        match search_user {
            Ok(val) => {
                match val {
                    Some(user_find) => {
                        user_exist = true;
                        user = user_find;
                    }
                    _ => {
                        user_exist = false;
                    }
                }
            }
            Err(_e) => {
                user_exist = false;
                println!("user not found");
            }
        }
        //warning from compiler but it's normal
        let mut chek_tag = false;
        //Generate the challenge
        let nonce = secretbox::gen_nonce();
        let nonce_encode = base64::encode(nonce);
        connection.send::<String>(&nonce_encode)?;
        connection.send::<String>(&user.salt)?;

        //Check the challenge answer
        let mut mac = HmacSha256::new_from_slice(user.password.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(nonce_encode.as_bytes());
        let challenge_compute = mac.finalize();
        let challenge_compute_encode = base64::encode(challenge_compute.into_bytes());
        let challenge_result = connection.receive::<String>()?;
        //assert_eq!(challenge_compute_encode, challenge_result);
        //Check if the tag sent by user is correct
        if challenge_compute_encode == challenge_result {
            chek_tag = true;
        } else {
            //Protection against timing attack
            chek_tag = false;
        }
        if user.fa_2 {
            connection.send::<String>(&SUCCESS.to_string())?;
            let signature_result = connection.receive::<String>()?;
            let signature_result_decode = base64::decode(signature_result).unwrap();

            //Transform the public key
            let encoded_point: EncodedPoint = match EncodedPoint::from_bytes(&user.public_key) {
                Ok(encoded_point) => encoded_point,
                Err(_) => {
                    connection.send::<String>(&FAIL.to_string())?;
                    return Err("The public key is invalid".into());
                }
            };
            let verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point)?;
            let signature_by_server = p256::ecdsa::Signature::from_der(&signature_result_decode)?;
            match verifying_key.verify(&nonce_encode.as_bytes(), &signature_by_server) {
                Ok(_) => {
                    println!("Signature is valid");
                    if !chek_tag || !user_exist {
                        connection.send::<String>(&FAIL.to_string())?;
                        return Err("Authentication failed".into());
                    }
                    connection.send::<String>(&SUCCESS.to_string())?;
                    return Ok(Some(user));
                }
                Err(e) => {
                    println!("Signature is invalid {}", e);
                    connection.send::<String>(&FAIL.to_string())?;
                    return Err("Authentication failed".into());
                }
            }
        } else {
            //2FA inactive
            connection.send::<String>(&FAIL.to_string())?;
            if !chek_tag {
                connection.send::<String>(&FAIL.to_string())?;
                return Err("Authentication failed".into());
            } else {
                connection.send::<String>(&SUCCESS.to_string())?;
                return Ok(Some(user));
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub email: String,
    pub password: String,
    pub salt: String,
    pub public_key: Vec<u8>,
    pub fa_2: bool,
}
