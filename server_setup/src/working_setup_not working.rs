use axum::{Router, routing::{get, post}, extract::{State, Json}};
use serde::{Serialize, Deserialize};
use std::{sync::{Arc, Mutex}, net::SocketAddr};
use tokio::net::TcpListener;
use lettre::message::{header, Message};
use lettre::{SmtpTransport, Transport, transport::smtp::authentication::Credentials};



#[derive(Debug, Deserialize, Clone, Serialize)]
struct Email{
    to: Option<String>,
    header: String,
    message: String,
    senders: Vec<String>,
    group_signature: String,
}

type EmailDatabase = Arc<Mutex<Vec<Email>>>;

async fn send_list_emails(State(emal_list): State<EmailDatabase>) -> Json<Vec<Email>> {
    let data = emal_list.lock().unwrap(); // Access the vector
    Json(data.clone())   
}

async fn receive_email(State(emal_list): State<EmailDatabase>, Json(email): Json<Email>) -> String{
    if email.group_signature == "I know a password".to_string(){
        let mut data = emal_list.lock().unwrap();
        data.push(email.clone());
        let email = Message::builder()
                            .from("0xparc.group.signature@gmail.com".parse().unwrap())
                            .to(email.to.unwrap_or("for.proga2@gmail.com".to_string()).parse().unwrap())
                            .subject(email.header)
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(email.message)
                            .unwrap();
        let creds = Credentials::new("0xparc.group.signature@gmail.com".into(), "PWATaLw9wM16kZB8NkP2".into());
        let mailer = SmtpTransport::relay("smtp.gmail.com").unwrap().credentials(creds).build();
        match mailer.send(&email){
            Ok(response) => {
                format!("Email sent! Server said: {:?}", response) }
            Err(e) => {
                format!("Failed to send email: {:?}", e)
            }
        }
    } else {
        format!("Sorry, signature is incorrect")
    }
}

#[tokio::main]
async fn main() {
    let emails : EmailDatabase = Arc::new(Mutex::new(Vec::new()));
    let router = Router::new()
                    .route("/", get(send_list_emails))
                    .route("/", post(receive_email))
                    .with_state(emails);

    let addr = SocketAddr::from(([127,0,0,1], 8000));
    let tcp = TcpListener::bind(&addr).await.unwrap();

    axum::serve(tcp, router).await.unwrap();
}