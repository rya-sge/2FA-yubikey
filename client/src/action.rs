use serde::{Serialize, Deserialize};
use crate::connection::Connection;
use std::error::Error;

use strum::IntoEnumIterator;
use strum_macros::{EnumString, EnumIter};
use read_input::prelude::input;
use crate::constante::{SUCCESS, FAIL};


/// `Action` enum is used to perform logged operations:
/// -   Enable/Disable 2fa authentication
#[derive(Serialize, Deserialize, Debug, EnumString, EnumIter)]
pub enum Action {
    #[strum(serialize = "Enable/Disable 2FA", serialize = "1")]
    Switch2FA,
    #[strum(serialize = "Exit", serialize = "2")]
    Logout
}

impl Action {
    pub fn display() {
        let mut actions = Action::iter();
        for i in 1..=actions.len() { println!("{}.\t{:?}", i, actions.next().unwrap()); }
    }

    pub fn perform(&self, mut connection: &mut Connection) -> Result<bool, Box<dyn Error>> {
        connection.send(self)?;

        match self {
            Action::Switch2FA => Action::switch_2fa(&mut connection),
            Action::Logout => Ok(false)
        }
    }

    fn switch_2fa(connection: &mut Connection) -> Result<bool, Box<dyn Error>> {

        println!("Activate 2FA : enter [1]");
        println!("Deactivate 2FA : enter [2]");
        let respond =  input::<String>().get();
        if respond == "1".to_string() {
            connection.send::<String>(&SUCCESS.to_string())?;
        }else if respond == "2".to_string()  {
            connection.send::<String>(&FAIL.to_string())?;
        }
        Ok(true)
    }
}
