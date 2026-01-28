use crate::transport::{TcpIncoming, TcpOutgoing};

use anyhow::Result;
use futures::SinkExt;
use givre::ciphersuite::{AdditionalEntropy, Ciphersuite, Ed25519 as CsEd25519};
use givre::generic_ec::{Scalar, curves::Ed25519};
use givre::key_share::DirtyKeyShare;
use givre::keygen::key_share::Valid;
use givre::signing;
use givre::signing::{aggregate::Signature, full_signing::Msg};
use rand_core::OsRng;
use round_based::{MpcParty, Outgoing};
use serde::{Deserialize, Serialize};
use solana_instruction::Instruction;
use solana_message::Message;
use solana_program::instruction::AccountMeta;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use std::{convert::TryInto, str::FromStr};
use tokio::net::TcpStream;
use tracing::error;

type SigningMsg = Msg<Ed25519>;

/// Runs the distributed signing phase using the participant's valid key share.
/// Returns the `r` and `z` components of the threshold signature for broadcasting.
///
/// # Arguments
/// * `id` - Signer ID
/// * `valid_shares` - Participant's valid key share from DKG
/// * `socket` - TCP stream used for signing phase communication
/// * `message_data` - The serialized message bytes to be signed
pub async fn run_signing_phase(
    id: u64,
    valid_shares: Valid<DirtyKeyShare<Ed25519>>,
    socket: tokio::net::TcpStream,
    message_data: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let std_stream: std::net::TcpStream = socket.into_std()?;
    std_stream.set_nonblocking(true)?;
    let std_stream_sign: std::net::TcpStream = std_stream.try_clone()?;

    // Convert standard TCP stream into tokio streams for async communication
    let reader_stream_sign = TcpStream::from_std(std_stream_sign.try_clone()?)?;
    let writer_stream_sign = TcpStream::from_std(std_stream_sign)?;

    // Wrap streams in TcpIncoming/TcpOutgoing to be used by the MPC party
    let incoming = TcpIncoming::<SigningMsg>::new(reader_stream_sign, id);
    let outgoing = TcpOutgoing::<SigningMsg>::new(writer_stream_sign);

    // Create the MPC party for threshold signing
    let party = MpcParty::connected((incoming, outgoing));
    let i = id as u16;

    // TODO: update this dynamically based on the number of signers
    let parties_indexes_at_keygen: [u16; 2] = [0, 1];
    let key_share: Valid<DirtyKeyShare<Ed25519>> = valid_shares;

    // Distributed signing
    let mut rng = OsRng;
    let signature: Signature<CsEd25519> = match signing::<CsEd25519>(
        i,
        &key_share,
        &parties_indexes_at_keygen,
        &message_data,
    )
    .sign(&mut rng, party)
    .await
    {
        Ok(sig) => sig,
        Err(e) => {
            error!("Threshold signing failed: {:?}", e);
            return Err(e.into());
        }
    };

    // Extract r and z scalars from the signature
    let r_bytes = signature.r.to_bytes();
    let z_bytes_generic: <CsEd25519 as Ciphersuite>::ScalarBytes =
        <Scalar<Ed25519> as AdditionalEntropy<CsEd25519>>::to_bytes(&signature.z);
    let z_bytes: [u8; 32] = z_bytes_generic.as_ref().try_into().unwrap();

    Ok((r_bytes.as_ref().to_vec(), z_bytes.to_vec()))
}

/// Generates a Solana transfer message to be signed.
///
/// # Arguments
/// * `from_address` - Sender's Solana address
/// * `to_address` - Receiver's Solana address
/// * `lamports` - Amount to transfer in lamports
pub fn create_transfer_message(
    from_address: &str,
    to_address: &str,
    lamports: u64,
) -> Result<Message> {
    const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
    let rpc = RpcClient::new("https://api.devnet.solana.com".to_string());

    let from = Pubkey::from_str(from_address)?;
    let to = Pubkey::from_str(to_address)?;

    let mut data = vec![];
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());

    let instruction = Instruction {
        program_id: Pubkey::from_str(SYSTEM_PROGRAM_ID)?,
        accounts: vec![AccountMeta::new(from, true), AccountMeta::new(to, false)],
        data,
    };

    let mut message = Message::new(&[instruction], Some(&from));
    message.recent_blockhash = rpc.get_latest_blockhash()?;

    Ok(message)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MessageToSign {
    pub data: Vec<u8>,
}

/// Sends a serialized Solana message to another server for coordinated signing.
///
/// # Arguments
/// * `std_stream_send` - TCP stream connected to the peer server
/// * `message` - The Solana message to send
pub async fn send_message_to_other_server(
    std_stream_send: std::net::TcpStream,
    message: Message,
) -> Result<()> {
    let writer_stream_send = TcpStream::from_std(std_stream_send)?;
    let mut outgoing_send = TcpOutgoing::<MessageToSign>::new(writer_stream_send);

    let message_data: Vec<u8> = message.serialize();
    let signing_msg = MessageToSign {
        data: message_data.clone(),
    };

    let outgoing_msg = Outgoing::p2p(1, signing_msg);
    if let Err(e) = outgoing_send.send(outgoing_msg).await {
        error!("Failed to send message to other server: {:?}", e);
        return Err(e.into());
    }

    Ok(())
}
