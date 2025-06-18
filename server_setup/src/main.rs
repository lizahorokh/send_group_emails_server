use axum::{Router, routing::{get, post}, extract::{State, Json}};
use serde::{Serialize, Deserialize};
use std::{sync::{Arc, Mutex}, net::SocketAddr};
use tokio::net::TcpListener;
use lettre::message::{header, Message};
use lettre::{SmtpTransport, Transport, transport::smtp::authentication::Credentials};

mod fetch_data/main;
mod verify_signature/main;
use fetch_data:: {create_pb_signals};
use verify_signature :: {verify_proof};


#[derive(Debug, Deserialize, Clone, Serialize)]
struct Email{
    to: Option<String>,
    header: String,
    message: String,
    senders: Vec<&str>,
    group_signature: String,
}

type EmailDatabase = Arc<Mutex<Vec<Email>>>;

async fn send_list_emails(State(emal_list): State<EmailDatabase>) -> Json<Vec<Email>> {
    let data = emal_list.lock().unwrap(); // Access the vector
    Json(data.clone())   
}

fn create_the_message(list_senders: Vec<&str>, message : String) -> String{
    let mut result :String = "".to_string();
    result = message.copy() + "\n Best, \n Participant of a group : \n";
    for sender in list_senders{
        result = result + sender + "\n";
    }
    result 
}

async fn receive_email(State(emal_list): State<EmailDatabase>, Json(email): Json<Email>) -> String{
    let mut pb_signals: Vec<String> = create_pb_signals(email.senders, email.header + email.message);

    if verify_proof(email.group_signature, pb_signals.to_string()).unwrap(){
        let mut data = emal_list.lock().unwrap();
        data.push(email.clone());
        let email = Message::builder()
                            .from("0xparc.group.signature@gmail.com".parse().unwrap())
                            .to(email.to.unwrap_or("for.proga2@gmail.com".to_string()).parse().unwrap())
                            .subject(email.header)
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(create_the_message(email.senders, email.message))
                            .unwrap();
        let creds = Credentials::new("0xparc.group.signature@gmail.com".into(), "ybng swmx ioor ehwg".into());
        let mailer = SmtpTransport::relay("smtp.gmail.com").unwrap().credentials(creds).build();
        match mailer.send(&email){
            Ok(response) => {
                format!("Email sent! Server said: {:?}", response) }
            Err(e) => {
                format!("Failed to send email: {:#?}", e)
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
