use async_net::{TcpListener, TcpStream};
use log::info;
use russh::client::Config;
use russh::keys::*;
use russh::*;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs /*unix::SocketAddr*/};

pub struct Client {}

#[derive(Debug)]
pub enum ClientErr {
    AuthErr(String),
    Err,
    ChannelErr,
}

impl From<russh::Error> for ClientErr {
    fn from(value: russh::Error) -> Self {
        Self::Err
    }
}

impl client::Handler for Client {
    type Error = ClientErr;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        info!("check_server_key: {server_public_key:?}");
        Ok(true)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        info!("data on channel {:?}: {}", channel, data.len());
        Ok(())
    }
}

pub struct Session {
    session: client::Handle<Client>,
}

impl Session {
    async fn connect<P: AsRef<Path>, A: ToSocketAddrs>(
        key_path: P,
        openssh_cert_path: Option<P>,
        user: impl Into<String>,
        addrs: A,
    ) -> Result<Self, ClientErr> {
        let key_pair = load_secret_key(key_path, None)?;

        let config = Config {
            nodelay: true,
            ..Default::default()
        };

        // load ssh certificate
        let mut openssh_cert = None;
        if openssh_cert_path.is_some() {
            openssh_cert = Some(load_openssh_certificate(openssh_cert_path.unwrap())?);
        }

        let config = Arc::new(config);
        let sh = Client {};

        let mut session = client::connect(config, addrs, sh).await?;
        // use publickey authentication, with or without certificate
        if openssh_cert.is_none() {
            let auth_res = session
                .authenticate_publickey(
                    user,
                    PrivateKeyWithHashAlg::new(
                        Arc::new(key_pair),
                        session.best_supported_rsa_hash().await?.flatten(),
                    ),
                )
                .await?;

            if !auth_res.success() {
                return Err(ClientErr::AuthErr(
                    "Authentication (with publickey) failed".to_string(),
                ));
            }
        } else {
            let auth_res = session
                .authenticate_openssh_cert(user, Arc::new(key_pair), openssh_cert.unwrap())
                .await?;

            if !auth_res.success() {
                return Err(ClientErr::AuthErr(
                    "Authentication (with publickey+cert) failed".to_string(),
                ));
            }
        }

        Ok(Self { session })
    }

    async fn chanel_event<C: From<(ChannelId, ChannelMsg)>>(
        ch: C,
        buf: Vec<u8>,
        is_stream_closed: bool,
        mut stream: TcpStream,
    ) {
        //let r =
    }

    async fn call(
        &mut self,
        mut stream: TcpStream,
        originator_addr: SocketAddr,
        forward_addr: SocketAddr,
    ) -> Result<(), ClientErr> {
        let mut channel: Channel<client::Msg> = self
            .session
            .channel_open_direct_tcpip(
                forward_addr.ip().to_string(),
                forward_addr.port().into(),
                originator_addr.ip().to_string(),
                originator_addr.port().into(),
            )
            .await?;
        // There's an event available on the session channel
        let mut stream_closed = false;
        let mut buf = vec![0; 65536];
        loop {
            // Handle one of the possible events:
            tokio::select! {
                // There's socket input available from the client
                r = stream.read(&mut buf), if !stream_closed => {
                    match r {
                        Ok(0) => {
                            stream_closed = true;
                            channel.eof().await?;
                        },
                        // Send it to the server
                        Ok(n) => channel.data(&buf[..n]).await?,
                        Err(e) => return Err(e.into()),
                    };
                },
                // There's an event available on the session channel
                Some(msg) = channel.wait() => {
                    match msg {

                        // Write data to the client
                        ChannelMsg::Data { ref data } => {
                            let res = stream.write_all(data).await;
                            if res.is_err(){

                            }
                        }
                        ChannelMsg::Eof => {
                            if !stream_closed {
                                channel.eof().await?;
                            }
                            break;
                        }
                        ChannelMsg::WindowAdjusted { new_size:_ }=> {
                            // Ignore this message type
                        }
                        _ => {todo!()}
                    }
                },
            }
        }
        Ok(())
    }

    async fn close(&mut self) -> Result<(), ClientErr> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}
