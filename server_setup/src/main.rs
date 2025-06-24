use axum::{Router, routing::{get, post}, extract::{State, Json}};
use serde::{Serialize, Deserialize};
use std::{sync::{Arc, Mutex}, net::SocketAddr};
use serde_json;
use tokio::net::TcpListener;
use lettre::message::{header, Message};
use lettre::{SmtpTransport, Transport, transport::smtp::authentication::Credentials};
use rusqlite::{params, Connection, Result};
use fetch_data_lib :: {create_pb_signals};
use verify_proof_lib :: {verify_proof};
use database_lib::{Email, create_table, insert_email_to_database, get_email_from_database, list_all_emails_in_database};
use chrono::prelude::*;

#[derive(Debug, Deserialize, Clone, Serialize, PartialEq)]
pub struct EmailReceived{
    pub to: Option<String>, 
    pub header: String,
    pub message: String,
    pub senders: Vec<String>,
    pub group_signature: String
}

type EmailDatabase = Arc<Mutex<Connection>>;
// show all emails in database
//todo: add better error handling
async fn send_list_emails(State(database_conn): State<EmailDatabase>) -> Json<Vec<Email>> {
    let data = list_all_emails_in_database(&database_conn.lock().unwrap()).unwrap(); // Access the vector
    Json(data.clone())   
}

async fn create_the_message(list_senders: Vec<String>, message : String) -> String{
    let mut result :String = "".to_string();
    result = message + "\nBest, \nParticipant of a group : \n";
    for sender in list_senders{
        result = result + &sender + "\n";
    }    result 
}

async fn receive_email(State(database_conn): State<EmailDatabase>, Json(email): Json<EmailReceived>) -> String{
    let date: String= Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    
    let email_database = Email{to: email.to.clone(), header: email.header.clone(), message: email.message.clone(), senders: email.senders.clone(), group_signature: email.group_signature.clone(), date: date.clone()};

    let to_addr  = email.to.clone().unwrap_or_else(|| "sansome-talk@0xparc.org".into());
    let subject   = email.header.clone();      // or borrow &email.header
    let pb_signals = match create_pb_signals(email.senders.clone(), &email.message.clone()).await {
        Ok(body)  => body,
        Err(err) => return format!("Sorry, could not process your request. \n {err}"),
    };
    let mut text = create_the_message(email.senders.clone(), email.message.clone()).await;
    let input_pb_signals = match serde_json::to_string(&pb_signals){
        Ok(body) => body,
        Err(err) => return format!("Error processing public signals. Check the input fomating."),
    };
    let flag = verify_proof(&email.group_signature, &input_pb_signals,  &"../verification_key.json".to_string()).await;
   
    match flag {
        Ok(body) => { 
            if body {
                let email_id = insert_email_to_database(&database_conn.lock().unwrap(), &email_database).unwrap();
                
                let letter = Message::builder()
                                    .from("kudos@0xparc.org".parse().unwrap())
                                    .to(to_addr.parse().unwrap())
                                    .subject(subject)
                                    .header(header::ContentType::TEXT_PLAIN)
                                    .body(text + &format!("\n \n Date: {} \n Email id: {} \n \n Group Signature: {} \n (Trust us bro)", date, email_id, &email.group_signature))
                                    .unwrap();
                let creds = Credentials::new("kudos@0xparc.org".into(), "szmi aljp ugko evld".into());
                let mailer = SmtpTransport::relay("smtp.gmail.com").unwrap().credentials(creds).build();
                match mailer.send(&letter){
                    Ok(response) => {
                        return format!("Email sent! Server said: {:?}", response); },
                    Err(e) => {
                        return format!("Failed to send email: {:#?}", e);
                    }
                };
            } else {
                return format!("Sorry, signature is incorrect");
            }
        },
        Err(err) => return format!("Sorry, could not verify proof due to the {err}."),
    };
    return "End of the function".to_string();
}

#[tokio::main]
async fn main() {
    let database: EmailDatabase =  Arc::new(Mutex::new(Connection::open("emails.db").expect("Failed to open database")));
    create_table(&database.lock().unwrap()).expect("Failed to create table");
    
    let router = Router::new()
                    .route("/", get(send_list_emails))
                    .route("/", post(receive_email))
                    .with_state(database);

    let addr = SocketAddr::from(([127,0,0,1], 8000));
    let tcp = TcpListener::bind(&addr).await.unwrap();

    axum::serve(tcp, router).await.unwrap();
}
