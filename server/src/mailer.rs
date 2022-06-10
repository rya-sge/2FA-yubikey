use lettre::smtp::authentication::IntoCredentials;
use lettre::{SmtpClient, Transport};
use lettre_email::EmailBuilder;

pub fn send_mail(email: &String, subject: &String, token: &String) {
    let smtp_address = "smtp.gmail.com";
    let username = "PUT YOUR EMAIL HERE";
    let password = "PUT_YOUR_APPLICATION_KEY_HERE";

    let email = EmailBuilder::new()
        .to(email.to_string())
        .from(username)
        .subject(subject.to_string())
        .text(token.to_string())
        .build()
        .unwrap()
        .into();

    let credentials = (username, password).into_credentials();

    let mut client = SmtpClient::new_simple(smtp_address)
        .unwrap()
        .credentials(credentials)
        .transport();

    let _result = client.send(email);
}
