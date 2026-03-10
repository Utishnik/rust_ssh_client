use log::info;
use russh::keys::*;
use russh::*;

pub struct Client {}

#[derive(Debug)]
pub enum ClientErr{
    Err,
}

impl From<russh::Error> for ClientErr{
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