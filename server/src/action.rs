use serde::{Serialize, Deserialize};
use crate::connection::Connection;
use std::error::Error;

use crate::authentication::User;
use crate::database::Database;
use crate::constante;

/// `Action` enum is used to perform logged operations:
/// -   Enable/Disable 2fa authentication
#[derive(Serialize, Deserialize, Debug)]
pub enum Action {
    Switch2FA,
    Logout,
    Authenticate,
}

impl Action {
    pub fn perform(user: &mut User, connection: &mut Connection) -> Result<bool, Box<dyn Error>> {
        match connection.receive()? {
            Action::Switch2FA => Action::switch_2fa(user, connection),
            Action::Authenticate => Action::authenticate(),
            Action::Logout => {
                println!("User logout");
                Ok(false)
            }
        }
    }

    fn switch_2fa(user: &mut User, connection: &mut Connection) -> Result<bool, Box<dyn Error>> {
        let success_string = constante::SUCCESS.to_string();
        let fail_string = constante::FAIL.to_string();
        let result = connection.receive::<String>()?;
        if result == fail_string {
            println!("Deactivate 2FA");
            user.fa_2 = false;
            Database::insert(&user).unwrap();
        } else if result == success_string {
            println!("Activate 2FA");
            user.fa_2 = true;
            Database::insert(&user).unwrap();
        }
        Ok(true)
    }

    fn authenticate() -> Result<bool, Box<dyn Error>> {
        println!("Hello");

        Ok(true) // TODO
    }
}
