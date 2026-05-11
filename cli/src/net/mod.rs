pub mod cli_peer;
pub mod iroh_path;
pub mod phone_connection;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

pub(crate) async fn recv_all(recv: &mut iroh::endpoint::RecvStream) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(
        recv.read_to_end(1024 * 1024)
            .await
            .context("read recv stream")?,
    ))
}
