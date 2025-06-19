use axum::{Router, routing::{get, post}, extract::{State, Json}};
use serde::{Serialize, Deserialize};
use std::{sync::{Arc, Mutex}, net::SocketAddr};
use serde_json;
use tokio::net::TcpListener;
use lettre::message::{header, Message};
use lettre::{SmtpTransport, Transport, transport::smtp::authentication::Credentials};

use fetch_data_lib :: {create_pb_signals};
use verify_proof_lib :: {verify_proof};


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

async fn create_the_message(list_senders: Vec<String>, message : String) -> String{
    let mut result :String = "".to_string();
    result = message + "\n Best, \n Participant of a group : \n";
    for sender in list_senders{
        result = result + &sender + "\n";
    }
    result 
}

async fn receive_email(State(emal_list): State<EmailDatabase>, Json(email): Json<Email>) -> String{
    let to_addr  = email.to.clone()                     
        .unwrap_or_else(|| "for.proga2@gmail.com".into());

    let subject   = email.header.clone();      // or borrow &email.header
    let body_text = email.message.clone();
    let pb_signals: Vec<String> = create_pb_signals(email.senders.clone(), &email.message.clone()).await;
    //let mut text = create_the_message(email.senders.clone(), email.message.clone()).await;
    println!("Got public signals {pb_signals:?}");
    if verify_proof(&email.group_signature, &serde_json::to_string(&pb_signals).unwrap(),  &"../verification_key.json".to_string()).await.unwrap(){
        let mut data = emal_list.lock().unwrap();
        data.push(email.clone());
        let letter = Message::builder()
                            .from("0xparc.group.signature@gmail.com".parse().unwrap())
                            .to(to_addr.parse().unwrap())
                            .subject(subject)
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(body_text)
                            .unwrap();
        let creds = Credentials::new("0xparc.group.signature@gmail.com".into(), "ybng swmx ioor ehwg".into());
        let mailer = SmtpTransport::relay("smtp.gmail.com").unwrap().credentials(creds).build();
        match mailer.send(&letter){
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