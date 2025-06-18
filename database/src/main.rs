use rusqlite::{params, Connection, Result};

#[derive(Debug, Clone)]
struct Email{
    id: i64,
    recipient: Option<String>,
    header: Option<String>,
    message: Option<String>,
    senders: Vec<String>, // could also be github repo link ??
    group_signature: String,
    date: String // If senders is the repo link, then we need access date
}


use rusqlite::Error as SqliteError;


fn create_table(conn: &Connection) -> Result<usize, SqliteError> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT,
            header TEXT,
            message TEXT,
            senders TEXT NOT NULL,
            group_signature TEXT NOT NULL,
            date TEXT NOT NULL
        )",
        [],
    )
}

// assuming senders is a vector of strings
// add proper error handling
fn insert_email(conn: &Connection, email: &Email) -> Result<i64, SqliteError> {
    conn.execute(
        "INSERT INTO emails (recipient, header, message, senders, group_signature, date) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![email.recipient, email.header, email.message, email.senders.join(","), email.group_signature, email.date],
    )?;
    Ok(conn.last_insert_rowid())
}

fn get_email(conn: &Connection, id: i64) -> Result<Email, SqliteError> {
    let mut stmt = conn.prepare("SELECT id, recipient, header, message, senders, group_signature, date FROM emails WHERE id = ?1")?;
    let email_iter = stmt.query_map(params![id], |row| {
        Ok(Email {
            id: row.get(0)?,
            recipient: row.get(1)?,
            header: row.get(2)?,
            message: row.get(3)?,
            senders: row.get::<_, String>(4)?.split(',').map(String::from).collect(),
            group_signature: row.get(5)?,
            date: row.get(6)?,
        })
    })?;

    for email in email_iter {
        return email;
    }
    Err(SqliteError::QueryReturnedNoRows)
}


fn main() {
    let conn = Connection::open("emails.db").expect("Failed to open database");
    create_table(&conn).expect("Failed to create table");
    let mut email = Email {
        id: 0, // This will be auto-generated
        recipient: Some("duruozer13@gmail.com".to_string()),
        header: Some("Test Email".to_string()),
        message: Some("This is a test email.".to_string()),
        senders: vec!["sender1".to_string(), "sender2".to_string()],
        group_signature: "I know a password".to_string(),
        date: "2025-06-18".to_string(),
    };
    let email_id = insert_email(&conn, &email).expect("Failed to insert email");
    email.id = email_id; // Update the email struct with the new ID
    // TODO: then send the email
    println!("Email inserted successfully with ID: {}", email_id);
    match get_email(&conn, email_id as i64) {
        Ok(email) => println!("Retrieved email: {:?}", email),
        Err(e) => println!("Error retrieving email: {}", e),
    };

}
