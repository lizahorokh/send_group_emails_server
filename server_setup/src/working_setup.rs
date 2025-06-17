use axum::{Router, routing::{get, post}, extract::{State, Json}};
use serde::{Serialize, Deserialize};
use std::{sync::{Arc, Mutex}, net::SocketAddr};
use tokio::net::TcpListener;

#[derive(Debug, Deserialize, Clone, Serialize)]
struct Message{
    sender: String,
    message: String,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
struct Request{
    password: String,
    message: Message,
}



type MessageDatabase = Arc<Mutex<Vec<Message>>>;

async fn send_list_messages(State(messages): State<MessageDatabase>) -> Json<Vec<Message>> {
    let data = messages.lock().unwrap(); // Access the vector
    Json(data.clone())   
}

async fn receive_message(State(messages): State<MessageDatabase>, Json(request): Json<Request>) -> String{
    if request.password == "I know a password".to_string(){
        let mut data = messages.lock().unwrap();
        data.push(request.message.clone());
        format!("We received message from {}", request.message.sender)
    } else {
        format!("Sorry, password is incorrect")
    }
}

#[tokio::main]
async fn main() {
    let messages : MessageDatabase = Arc::new(Mutex::new(Vec::new()));
    messages.lock().unwrap().push(Message{sender: "Liza".to_string(), message : "Hello world!".to_string()});

    let router = Router::new()
                    .route("/", get(send_list_messages))
                    .route("/", post(receive_message))
                    .with_state(messages);

    let addr = SocketAddr::from(([127,0,0,1], 8000));
    let tcp = TcpListener::bind(&addr).await.unwrap();

    axum::serve(tcp, router).await.unwrap();
}