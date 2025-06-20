use rusqlite::{params, Connection, Result};
use serde::{Serialize, Deserialize};

#[derive(Debug, Deserialize, Clone, Serialize, PartialEq)]
pub struct Email{
    pub to: Option<String>, 
    pub header: String,
    pub message: String,
    pub senders: Vec<String>,
    pub group_signature: String,
    pub date: String
}


use rusqlite::Error as SqliteError;


pub fn create_table(conn: &Connection) -> Result<usize, SqliteError> {
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
pub fn insert_email_to_database(conn: &Connection, email: &Email) -> Result<i64, SqliteError> {
    conn.execute(
        "INSERT INTO emails (recipient, header, message, senders, group_signature, date) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![email.to, email.header, email.message, email.senders.join(","), email.group_signature, email.date],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn get_email_from_database(conn: &Connection, id: i64) -> Result<Email, SqliteError> {
    let mut stmt = conn.prepare("SELECT id, recipient, header, message, senders, group_signature, date FROM emails WHERE id = ?1")?;
    let email_iter = stmt.query_map(params![id], |row| {
        Ok(Email {
            to: row.get(1)?,
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

pub fn list_all_emails_in_database(conn : &Connection) -> Result<Vec<Email>, SqliteError>{
    let mut stmt = conn.prepare("SELECT * FROM emails")?;
    let email_iter = stmt.query_map([], |row| {
        Ok(Email {
            to: row.get(1)?,
            header: row.get(2)?,
            message: row.get(3)?,
            senders: row.get::<_, String>(4)?.split(',').map(String::from).collect(),
            group_signature: row.get(5)?,
            date: row.get(6)?,
        })
    });
    let mut all_emails : Vec<Email> = Vec::new();
    for email in email_iter? {
        all_emails.push(email?);
    }
    Ok(all_emails)
}   

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let conn = Connection::open("emails.db").expect("Failed to open database");
        create_table(&conn).expect("Failed to create table");
        let email = Email {
            to: Some("duruozer13@gmail.com".to_string()),
            header: "Test Email".to_string(),
            message: "This is a test email.".to_string(),
            senders: vec!["sender1".to_string(), "sender2".to_string()],
            group_signature: "I know a password".to_string(),
            date: "2025-06-18".to_string(),
        };
        let email_id = insert_email_to_database(&conn, &email).expect("Failed to insert email");
        //email.id = email_id; // Update the email struct with the new ID
        // TODO: then send the email
        println!("Email inserted successfully with ID: {}", email_id);
        match get_email_from_database(&conn, email_id as i64) {
            Ok(test_email) => assert!(email == test_email),
            Err(e) => println!("Error retrieving email: {}", e),
        };
        match list_all_emails_in_database(&conn) {
            Ok(all_emails) => {
                assert!(all_emails.len() > 0);
                println!("All emails in database: {:?}", all_emails);
            },
            Err(e) => assert!(false, "Error listing emails: {}", e),
        };
    }
}
