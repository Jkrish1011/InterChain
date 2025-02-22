use alloy::{
    contract::{ContractInstance, Interface},
    dyn_abi::DynSolValue,
    network::{EthereumWallet, TransactionBuilder, NetworkWallet},
    providers::{Provider, ProviderBuilder, WsConnect},
    primitives::{address, U256, hex, B256,Log as ETHLog, LogData, FixedBytes, Address},
    rpc::types::{Filter,Log, TransactionRequest},
    signers::local::LocalSigner,
    sol
};

use std::str::from_utf8;
use alloy::sol_types::SolEvent;

use chrono::format::Fixed;
use hex as justHex;
use std::fs::read_to_string;
use rand::thread_rng;
use std::path::PathBuf;
use eyre::Result;
use futures_util::StreamExt;
use dotenv::dotenv;
use std::env;
use std::str::FromStr;
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::{sync::RwLock, time};
use serde::{Deserialize, Serialize};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    MessageSender,
    "contracts/abi/MessengeSender.json"
);

sol!{
    #[derive(Debug)]
    event MessageSent(
        bytes32 indexed messageId,
        address indexed sender,
        bytes message,
        uint256 timestamp,
        bytes signature
    );
}


sol!{
    #[derive(Debug)]
    event MessageReceived(
        bytes32 indexed messageId,
        address indexed sender,
        bytes message,
        uint256 timestamp
    );
}


#[derive(Debug, Serialize, Deserialize)]
struct Message {
    message_id: FixedBytes<32>,
    sender: Address,
    message: String,
    timestamp: U256
}

#[derive(Debug)]
struct RelayerConfig {
    ethereum_rpc: String,
    arbitrum_rpc: String,
    source_contract: Address,
    dest_contract: Address,
    private_key: String,
    eth_start_block: u64,
    arb_start_block: u64,
    confirmation_blocks: u64,
}


struct MessageRelayer {
    config: RelayerConfig,
    ethereum_provider: alloy::providers::fillers::FillProvider<alloy::providers::fillers::JoinFill<alloy::providers::fillers::JoinFill<alloy::providers::Identity, alloy::providers::fillers::JoinFill<alloy::providers::fillers::GasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::BlobGasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::NonceFiller, alloy::providers::fillers::ChainIdFiller>>>>, alloy::providers::fillers::WalletFiller<EthereumWallet>>, alloy::providers::RootProvider, alloy::network::Ethereum>,
    arbitrum_provider: alloy::providers::fillers::FillProvider<alloy::providers::fillers::JoinFill<alloy::providers::fillers::JoinFill<alloy::providers::Identity, alloy::providers::fillers::JoinFill<alloy::providers::fillers::GasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::BlobGasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::NonceFiller, alloy::providers::fillers::ChainIdFiller>>>>, alloy::providers::fillers::WalletFiller<EthereumWallet>>, alloy::providers::RootProvider, alloy::network::Ethereum>,
    processed_messages: Arc<RwLock<HashSet<B256>>>,
}

// async fn create_keystore() -> Result<()>{
//     let keystore_dir = PathBuf::from("./keystores/");
//      // Create the directory if it doesn't exist
//      std::fs::create_dir_all(&keystore_dir)?;
//     let mut rng = thread_rng();
//     let custom_filename = Some("account3-wallet-keystore.json");

//     // Private key of Alice, the first default Anvil account.
//     let p = &env::var("RELAYER_PRIVATE_KEY")?;
//     let private_key = hex!(p);

//     // Password to encrypt the keystore file with.
//     let password = env::var("RELAYER_PASSWORD")?;

//     // Create a keystore file from the private key of Alice, returning a [Wallet] instance.
//     let (wallet, file_path) = LocalSigner::encrypt_keystore(&keystore_dir, &mut rng, private_key, password, custom_filename)?;

//     let keystore_file_path = keystore_dir.join(custom_filename.unwrap());

//     println!("Wrote keystore for {} to {:?}", wallet.address(), keystore_file_path);

//     // Read the keystore file back.
//     let recovered_wallet = LocalSigner::decrypt_keystore(keystore_file_path.clone(), password)?;

//     println!(
//         "Read keystore from {:?}, recovered address: {}",
//         keystore_file_path,
//         recovered_wallet.address()
//     );

//     // Assert that the address of the original key and the recovered key are the same.
//     assert_eq!(wallet.address(), recovered_wallet.address());

//     // Display the contents of the keystore file.
//     let keystore_contents = read_to_string(keystore_file_path)?;

//     println!("Keystore file contents: {keystore_contents:?}");

//     Ok(())
// }

async fn read_from_keystore() -> Result<EthereumWallet> {
    // Password to decrypt the keystore file with.
    let password = env::var("RELAYER_PASSWORD")?;
    let pathOfKeyStore = env::var("RELAYER_KEYSTORE_PATH")?;
    let keystoreFileName = env::var("RELAYER_KEYSTORE_NAME")?;
    
    let keystore_file_path = PathBuf::from(pathOfKeyStore).join(keystoreFileName);

    let signer = LocalSigner::decrypt_keystore(keystore_file_path, password)?;
    let wallet = EthereumWallet::from(signer);

    Ok(wallet)
 
}

impl MessageRelayer {
    async fn new(config: RelayerConfig) -> Result<Self> {
        // Ethereum WebSocket Provider
        let ws = WsConnect::new(config.ethereum_rpc.clone());
        let wallet: EthereumWallet = read_from_keystore().await?;

        let ethereum_provider = ProviderBuilder::new()
            .wallet(wallet.clone())
            .on_ws(ws)
            .await?;
        
        // Arbitrum WebSocket Provider
        let ws_arbitrum = WsConnect::new(config.arbitrum_rpc.clone());
        
        
        let arbitrum_provider = ProviderBuilder::new()
            .wallet(wallet.clone())
            .on_ws(ws_arbitrum).await?;


        Ok(Self {
            config: config,
            ethereum_provider,
            arbitrum_provider,
            processed_messages: Arc::new(RwLock::new(HashSet::new())),
        })
    }

    async fn start(&self) -> Result<()> {
        // Concurrent task spawning
        let process_events = self.process_events();
        // let health_check = self.health_check();
        // let process_receiver_events = self.process_receiver_events();

        println!("::::: STARTING PROCESSES :::::");
        // Run all tasks concurrently
        tokio::try_join!(process_events)?;

        Ok(())
    }

    async fn process_events(&self) -> Result<()> {

        let sender_address = self.config.source_contract;
        
        // Create filter for MessageSent events
        let filter = Filter::new()
                    .address(sender_address)
                    .from_block(self.config.eth_start_block);

        let sub = self.ethereum_provider.subscribe_logs(&filter).await?;

        let mut stream = sub.into_stream();

        while let Some(log) = stream.next().await {
            let decoded_event = MessageSent::decode_log(&log.inner, false).unwrap();
            let decoded_message = from_utf8(&decoded_event.data.message).unwrap().to_string();
            let decoded_message_id = &decoded_event.data.messageId;
            let decoded_message_address = &decoded_event.data.sender;
            let decoded_message_timestamp= &decoded_event.data.timestamp;
            println!("Message ID:: {:?}", decoded_message_id.clone());
            let msg: Message = Message {
                sender: *decoded_message_address,
                message_id: *decoded_message_id,
                message: decoded_message,
                timestamp: *decoded_message_timestamp
            };
            self.relay_message(&msg).await?;
        }
        println!("Message Relayed!");
        Ok(())
    }

    async fn process_receiver_events(&self) -> Result<()> {

        let receiver_address = self.config.dest_contract;

        // Create filter for MessageSent events
        let filter = Filter::new()
                    .address(receiver_address)
                    .from_block(self.config.arb_start_block);

        let sub = self.arbitrum_provider.subscribe_logs(&filter).await?;

        let mut stream = sub.into_stream();

        while let Some(log) = stream.next().await {
            println!("{log:?}");
            let decoded_event = MessageReceived::decode_log(&log.inner, false).unwrap();
            let decoded_message = from_utf8(&decoded_event.data.message).unwrap().to_string();
            let decoded_message_id = &decoded_event.data.messageId;
            let decoded_message_address = &decoded_event.data.sender;
            let decoded_message_timestamp= &decoded_event.data.timestamp;

            let msg: Message = Message {
                sender: *decoded_message_address,
                message_id: *decoded_message_id,
                message: decoded_message,
                timestamp: *decoded_message_timestamp
            };
            self.relay_ack_message(&msg).await?;
        }
        
        Ok(())
    }

    async fn handle_message(&self, message: Message) -> Result<()> {
        // Check if message was already processed
        {
            let processed = self.processed_messages.read().await;
            if processed.contains(&message.message_id) {
                log::info!("Message {} already processed", message.message_id);
                return Ok(());
            }
        }

        // Verify the message
        if !self.verify_message(&message).await? {
            log::error!("Message verification failed for {}", message.message_id);
            return Ok(());
        }

        // Implement retry logic with exponential backoff
        let mut retry_count = 0;
        let max_retries = 5;
        
        while retry_count < max_retries {
            match self.relay_message(&message).await {
                Ok(_) => {
                    // Mark message as processed
                    let mut processed = self.processed_messages.write().await;
                    processed.insert(message.message_id);
                    log::info!("Successfully relayed message {}", message.message_id);
                    return Ok(());
                }
                Err(e) => {
                    retry_count += 1;
                    let delay = Duration::from_secs(2u64.pow(retry_count));
                    log::warn!(
                        "Relay attempt {} failed for message {}: {:?}. Retrying in {:?}",
                        retry_count,
                        message.message_id,
                        e,
                        delay
                    );
                    time::sleep(delay).await;
                }
            }
        }

        log::error!("Failed to relay message {} after {} attempts", message.message_id, max_retries);
        Ok(())
    }

    async fn verify_message(&self, message: &Message) -> Result<bool> {
        // Implement comprehensive message verification
        // 1. Verify signature
        let is_valid_signature = self.verify_signature(
            message.message_id,
            message.sender
        ).await?;

        if !is_valid_signature {
            return Ok(false);
        }

        // 2. Check message age
        let current_block = self.ethereum_provider
            .get_block_number()
            .await?;
        
        let message_block = message.timestamp.to::<u64>();
        if current_block - message_block > self.config.confirmation_blocks {
            log::warn!("Message {} is too old", message.message_id);
            return Ok(false);
        }

        // Add additional verification as needed
        Ok(true)
    }

    async fn verify_signature(
        &self,
        message_id: B256,
        sender: Address,
    ) -> Result<bool> {
        // Implement signature verification logic
        // This is a placeholder - implement actual verification
        Ok(true)
    }

    async fn relay_ack_message(&self, message: &Message) -> Result<()> {
        let path = PathBuf::from("./contracts/abi/MessengeSender.json");

        let address_string = "0xA014Ca018A22f96D00B920410834Bb1504B183E1";
        let wallet_address = Address::parse_checksummed(address_string, None).expect("Invalid address");
        
        let artifact = std::fs::read(path).expect("Failed to read artifact");
        let json: serde_json::Value = serde_json::from_slice(&artifact)?;

        let abi_value = json.get("abi").expect("Failed to get ABI from artifact");
        let abi = serde_json::from_str(&abi_value.to_string())?;

        let contract = ContractInstance::new(self.config.dest_contract, self.arbitrum_provider.clone(), Interface::new(abi));

        let message_id = DynSolValue::FixedBytes(message.message_id, 32);

        let tx_hash = contract.function("ackMessage", &[message_id])?.from(wallet_address).send().await?.watch().await?;

        println!("Tx_hash : {tx_hash}");

        Ok(())
    }

    async fn relay_message(&self, message: &Message) -> Result<()> {
        let path = PathBuf::from("./contracts/abi/MessengeReceiver.json");

        // If you have a hex string with "0x" prefix
        let address_string = &env::var("RELAYER_PUBLIC_ADDRESS")?;
        let wallet_address = Address::parse_checksummed(address_string, None).expect("Invalid address");
        
        let artifact = std::fs::read(path).expect("Failed to read artifact");
        let json: serde_json::Value = serde_json::from_slice(&artifact)?;

        let abi_value = json.get("abi").expect("Failed to get ABI from artifact");
        let abi = serde_json::from_str(&abi_value.to_string())?;

        let contract = ContractInstance::new(self.config.source_contract, self.ethereum_provider.clone(), Interface::new(abi));

        let message_id = DynSolValue::FixedBytes(message.message_id, 32);
        let sender = DynSolValue::Address(message.sender);
        let timestamp = DynSolValue::from(message.timestamp);

        let tx_hash = contract.function("receiveMessage", &[message_id, sender, timestamp])?.from(wallet_address).send().await?.watch().await?;

        println!("Tx_hash : {tx_hash}");

        Ok(())
    }

    
    async fn health_check(&self) -> Result<()> {
        let mut interval = time::interval(Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            
            // Check connection to both chains
            if let Err(e) = self.ethereum_provider.get_block_number().await {
                log::error!("Ethereum connection error: {:?}", e);
            }
            
            if let Err(e) = self.arbitrum_provider.get_block_number().await {
                log::error!("Arbitrum connection error: {:?}", e);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();
    
    // Load environment variables
    dotenv().ok();
    
    // Create relayer configuration
    let config = RelayerConfig {
        ethereum_rpc: env::var("ETHEREUM_RPC")?,
        arbitrum_rpc: env::var("ARBITRUM_RPC")?,
        source_contract: Address::from_str(&env::var("ETH_SEP_CONTRACT_ADDRESS")?)?,
        dest_contract: Address::from_str(&env::var("ARB_SEP_CONTRACT_ADDRESS")?)?,
        private_key: env::var("RELAYER_PRIVATE_KEY")?,
        eth_start_block: env::var("ETH_SEP_START_BLOCK")?.parse()?,
        arb_start_block: env::var("ARB_SEP_START_BLOCK")?.parse()?,
        confirmation_blocks: env::var("CONFIRMATION_BLOCKS")?.parse()?,
    };

    // Create and start the relayer
    let relayer = MessageRelayer::new(config).await?;
    relayer.start().await?;

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_variable_generation() {
        let log = Log {
            inner: ETHLog {
                address: "0x9c4928a42fd336ee3eb4ec853fc03a8d23ae7904".parse().unwrap(),
                data: LogData::new_unchecked(
                    vec![
                        "0xa9a06dcba5a4df240787afa75951f29bdd29d4229886487360b3d0f13d56a444".parse().unwrap(),
                        "0x0826a3ac8b3c61afe884bfcada224a4f44fd83517a48284b812d9867d721c81c".parse().unwrap(),
                        "0x000000000000000000000000a014ca018a22f96d00b920410834bb1504b183e1".parse().unwrap(),
                    ],
                    // Corrected hexadecimal string (even length)
                    "0x00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000067aee3a800000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000353594e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".parse().unwrap(),
                ),
            },
            block_hash: Some("0xdb2852c4fa133255db6b9a4d519f073d2779d48c6816de59365636602408d073".parse().unwrap()),
            block_number: Some(7704169 as u64),
            block_timestamp: None,
            transaction_hash: Some("0x88d038ba62297a2ad5d7a55ec29443aaf7eaf114e0b21721eab73bb724e088d6".parse().unwrap()),
            transaction_index: Some(93 as u64),
            log_index: Some(332 as u64),
            removed: false,
        };

        let decoded_event = MessageSent::decode_log(&log.inner, false).unwrap();
        let decoded_message = from_utf8(&decoded_event.data.message).unwrap();
        let decoded_message_id = &decoded_event.data.messageId;
        let decoded_message_address = &decoded_event.data.sender;
        let decoded_message_timestamp = &decoded_event.data.timestamp;

        println!("new format: {:?}", &decoded_message);
        // let message_decoded_bytes = justHex::decode(decoded.data.message).unwrap();
        // let message_decoded_string = from_utf8(&message_decoded_bytes).unwrap();
        // println!("{:?}", message_decoded_string);
    }
}