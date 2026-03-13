use crate::ssh_client::client::{Client, ClientErr};
use log::trace;
use std::io::Write;
use std::net::ToSocketAddrs;
use std::sync::Arc;//todo secure arc
use std::time::Duration;

#[derive(Debug,Clone)]
pub enum AuthMethod {
    // Password string
    Password(String),
    // Secret key path
    Key(String),
}

#[derive(Debug,Clone)]
pub struct ClientBuilder {
    username: String,
    auth: Option<AuthMethod>,
    connect_timeout: Duration,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            username: String::default(),
            auth: None,
            connect_timeout: Duration::from_secs(10),
        }
    }

    pub fn username<S: ToString>(&mut self, username: S) -> &mut Self {
        self.username = username.to_string();
        self
    }

    pub fn auth(&mut self, auth: AuthMethod) -> &mut Self {
        self.auth = Some(auth);
        self
    }

    pub fn connect_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.connect_timeout = timeout;
        self
    }
}
