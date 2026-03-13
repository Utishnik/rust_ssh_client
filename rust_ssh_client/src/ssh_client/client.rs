use async_net::{TcpListener as smol_tl, TcpStream as smol_ts};
use futures::channel;
use log::{info,trace};
use russh::client::Config;
use russh::keys::*;
use russh::*;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs /*unix::SocketAddr*/};
use crate::ssh_client::auth::auth_client_method::ClientBuilder;

pub struct Client {pub client_builder: ClientBuilder}

#[derive(Debug, Error)]
pub enum ClientErr {
    #[error("auth failed: {0}")]
    AuthErr(String),
    #[error("Err")]
    Err,
    #[error("channel error")]
    ChannelErr,
    #[error("load secret key error")]
    LoadSecretKeyErr,
    #[error("load openssh certificate error")]
    LoadOpensshCertificateErr,
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

pub struct RequestSubsystemHand<'a> {
    want_reply: &'a bool,
    name: &'a String,
}

pub enum ChannelMsgHand<'a> {
    Data(&'a CryptoVec),
    Eof,
    RequestSubsystem(RequestSubsystemHand<'a>),
}

#[inline(always)]
async fn check_msg(msg: &ChannelMsg) {
    match msg {
        // Write data to the client
        ChannelMsg::Data { data } => {
            let zxc: &CryptoVec = data;
            /*
            let res = stream.write_all(data).await;
            if res.is_err() {}
            */
        }
        ChannelMsg::Eof => {
            /*
            if !stream_closed {
                channel.eof().await?;
            }
            break;
            */
        }
        ChannelMsg::RequestSubsystem { want_reply, name } => {}
        ChannelMsg::SetEnv {
            want_reply,
            variable_name,
            variable_value,
        } => {}
        ChannelMsg::WindowAdjusted { new_size } => {
            // Ignore this message type
        }
        _ => {
            todo!()
        }
    }
}

async fn chanel_event<C: From<(ChannelId, ChannelMsg)> + Send + Sync + 'static>(
    channel: &mut Channel<C>,
    buf: &mut Vec<u8>,
    is_stream_closed: bool,
    mut stream: TcpStream,
) {
    let r = stream.read(buf);
    let w = channel.wait();
}

pub struct Session {
    session: client::Handle<Client>,
    client_builder: ClientBuilder,
}

impl Session {
    async fn connect<P: AsRef<Path>, A: ToSocketAddrs>(
        client_builder: ClientBuilder,
        key_path: P,
        openssh_cert_path: Option<P>,
        user: impl Into<String>,
        addrs: A,
    ) -> Result<Self, ClientErr> {
        let key_pair_wrap: Result<PrivateKey, russh::keys::Error> = load_secret_key(key_path, None);
        if key_pair_wrap.is_err() {
            return Err(ClientErr::LoadSecretKeyErr);
        }
        let key_pair: PrivateKey = key_pair_wrap.unwrap();

        let config = Config {
            nodelay: true,
            ..Default::default()
        };

        // load ssh certificate
        let mut openssh_cert: Option<Certificate> = None;
        if openssh_cert_path.is_some() {
            let load_cerf_wrap: Result<Certificate, ssh_key::Error> =
                load_openssh_certificate(openssh_cert_path.unwrap());
            if load_cerf_wrap.is_err() {
                return Err(ClientErr::LoadOpensshCertificateErr);
            }
            let load_cerf: Certificate = load_cerf_wrap.unwrap();
            openssh_cert = Some(load_cerf);
        }

        let config: Arc<Config> = Arc::new(config);
        let sh: Client = Client { client_builder: client_builder.clone() };

        let mut session = client::connect(config, addrs, sh).await?;
        // use publickey authentication, with or without certificate
        if openssh_cert.is_none() {
            trace!("connected");
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
                trace!("not success auth");
                return Err(ClientErr::AuthErr(
                    "Authentication (with publickey) failed".to_string(),
                ));
            }
        } else {
            let auth_res = session
                .authenticate_openssh_cert(user, Arc::new(key_pair), openssh_cert.unwrap())
                .await?;

            if !auth_res.success() {
                trace!("not success auth");
                return Err(ClientErr::AuthErr(
                    "Authentication (with publickey+cert) failed".to_string(),
                ));
            }
            trace!("auth success");
        }

        Ok(Self { session,client_builder })
    }

    /*
    async fn call_tokio(
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
    */

    async fn close(&mut self) -> Result<(), ClientErr> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}
