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
use tokio::task::JoinHandle;
use std::panic;
use std::future::Future;
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


sol! {
    #[derive(Debug)]
    contract MessageSender {
        event MessageSent(bytes32 indexed messageId,address indexed sender,bytes message,uint256 timestamp,bytes signature);
        event MessageAcknowledged(bytes32 indexed messageId,address indexed sender,bytes message);
    }
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
    relayer_private_key: String,
    relayer_public_address: String,
    eth_start_block: u64,
    arb_start_block: u64,
    eth_sep_contract_abi: String,
    arb_sep_contract_abi: String,
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
    let path_of_keystore = env::var("RELAYER_KEYSTORE_PATH")?;
    let keystore_filename = env::var("RELAYER_KEYSTORE_NAME")?;
    
    let keystore_file_path = PathBuf::from(path_of_keystore).join(keystore_filename);

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

    async fn start(self: Arc<Self>) -> Result<()> {
        // Clone the Arc for each task
        // Clone the Arc for each task
        let self_clone = Arc::clone(&self);

        // Spawn the task with the cloned Arc
        let process_eth_sep_events = tokio::spawn(async move {
            self_clone.process_eth_sep_events_with_recovery().await
        });

        let self_clone = Arc::clone(&self);
        
        let process_arb_sep_events = tokio::spawn(async move {
            self_clone.process_arb_sep_events_with_recovery().await
        });

        println!("::::: STARTING PROCESSES :::::");
        // Run all tasks concurrently
        tokio::try_join!(process_eth_sep_events, process_arb_sep_events)?;

        Ok(())
    }

    // New method with error recovery for Ethereum Sepolia events
    async fn process_eth_sep_events_with_recovery(&self) {
        const RETRY_DELAY: Duration = Duration::from_secs(5);
        
        loop {
            println!("::::: LISTENING TO SEPOLIA :::::");
            match self.process_eth_sep_events_inner().await {
                Ok(_) => {
                    // This shouldn't normally happen as the inner function has an infinite loop
                    println!("Ethereum Sepolia event processing completed unexpectedly. Restarting...");
                }
                Err(err) => {
                    eprintln!("Error in Ethereum Sepolia event processing: {:?}", err);
                    println!("Restarting Ethereum Sepolia event processing in {} seconds...", RETRY_DELAY.as_secs());
                }
            }
            
            // Wait before retrying
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }

    // Inner function with the actual event processing logic for Ethereum Sepolia
    async fn process_eth_sep_events_inner(&self) -> Result<()> {
        let sender_address = self.config.source_contract;
        
        let message_sent_topic = MessageSender::MessageSent::SIGNATURE_HASH;
        let message_acknowledged_topic = MessageSender::MessageAcknowledged::SIGNATURE_HASH;

        // Create filter for MessageSent events
        let filter = Filter::new()
                    .address(sender_address)
                    .from_block(self.config.eth_start_block);

        let sub = self.ethereum_provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();

        while let Some(log) = stream.next().await {
            println!("{log:?}");
            
            // Use match instead of if/else for better error handling
            match log.topics().get(0) {
                Some(topic) if *topic == message_sent_topic => {
                    match MessageSender::MessageSent::decode_log(&log.inner, false) {
                        Ok(decoded_event) => {
                            match from_utf8(&decoded_event.data.message) {
                                Ok(decoded_message_str) => {
                                    let msg: Message = Message {
                                        sender: decoded_event.data.sender,
                                        message_id: decoded_event.data.messageId,
                                        message: decoded_message_str.to_string(),
                                        timestamp: decoded_event.data.timestamp
                                    };

                                    if let Err(err) = self.relay_eth_sep_to_arb_sep_message(&msg).await {
                                        eprintln!("Error relaying message from ETH to ARB: {:?}", err);
                                        // Continue processing instead of returning the error
                                    } else {
                                        println!("Message Relayed from ETH to ARB successfully!");
                                    }
                                },
                                Err(err) => eprintln!("Error decoding message content: {:?}", err)
                            }
                        },
                        Err(err) => eprintln!("Error decoding MessageSent event: {:?}", err)
                    }
                },
                Some(topic) if *topic == message_acknowledged_topic => {
                    match MessageSender::MessageAcknowledged::decode_log(&log.inner, false) {
                        Ok(decoded_event) => {
                            match from_utf8(&decoded_event.data.message) {
                                Ok(decoded_message_str) => {
                                    println!("Message Acknowledged: {}", decoded_message_str);
                                    // Process acknowledgment if needed
                                },
                                Err(err) => eprintln!("Error decoding acknowledged message content: {:?}", err)
                            }
                        },
                        Err(err) => eprintln!("Error decoding MessageAcknowledged event: {:?}", err)
                    }
                },
                _ => eprintln!("Unknown event topic")
            }
        }
        
        Ok(())
    }

    // New method with error recovery for Arbitrum Sepolia events
    async fn process_arb_sep_events_with_recovery(&self) {
        const RETRY_DELAY: Duration = Duration::from_secs(5);
        
        loop {
            println!("::::: LISTENING TO ARBITRUM SEPOLIA :::::");
            match self.process_arb_sep_events_inner().await {
                Ok(_) => {
                    // This shouldn't normally happen as the inner function has an infinite loop
                    println!("Arbitrum Sepolia event processing completed unexpectedly. Restarting...");
                }
                Err(err) => {
                    eprintln!("Error in Arbitrum Sepolia event processing: {:?}", err);
                    println!("Restarting Arbitrum Sepolia event processing in {} seconds...", RETRY_DELAY.as_secs());
                }
            }
            
            // Wait before retrying
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }

    // Inner function with the actual event processing logic for Arbitrum Sepolia
    async fn process_arb_sep_events_inner(&self) -> Result<()> {
        let receiver_address = self.config.dest_contract;

        // Create filter for MessageSent events
        let filter = Filter::new()
                    .address(receiver_address)
                    .from_block(self.config.arb_start_block);

        let sub = self.arbitrum_provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();

        while let Some(log) = stream.next().await {
            println!("{log:?}");
            
            match MessageReceived::decode_log(&log.inner, false) {
                Ok(decoded_event) => {
                    match from_utf8(&decoded_event.data.message) {
                        Ok(decoded_message_str) => {
                            let msg: Message = Message {
                                sender: decoded_event.data.sender,
                                message_id: decoded_event.data.messageId,
                                message: decoded_message_str.to_string(),
                                timestamp: decoded_event.data.timestamp
                            };

                            if let Err(err) = self.relay_arb_sep_to_eth_sep_message(&msg).await {
                                eprintln!("Error relaying message from ARB to ETH: {:?}", err);
                                // Continue processing instead of returning the error
                            } else {
                                println!("Message Relayed from ARB to ETH successfully!");
                            }
                        },
                        Err(err) => eprintln!("Error decoding message content: {:?}", err)
                    }
                },
                Err(err) => eprintln!("Error decoding MessageReceived event: {:?}", err)
            }
        }
        
        Ok(())
    }
    
    async fn relay_arb_sep_to_eth_sep_message(&self, message: &Message) -> Result<()> {
        let path = PathBuf::from(&self.config.eth_sep_contract_abi);

        let address_string = &self.config.relayer_public_address;
        let wallet_address = Address::parse_checksummed(address_string, None).expect("Invalid address");
        
        let artifact = std::fs::read(path).expect("Failed to read artifact");
        let json: serde_json::Value = serde_json::from_slice(&artifact)?;

        let abi_value = json.get("abi").expect("Failed to get ABI from artifact");
        let abi = serde_json::from_str(&abi_value.to_string())?;

        let contract = ContractInstance::new(self.config.source_contract, self.ethereum_provider.clone(), Interface::new(abi));

        let message_id = DynSolValue::FixedBytes(message.message_id, 32);

        println!("::::: INITATING ETH SEPOLIA CALL :::::");
        let tx_hash = contract.function("ackMessage", &[message_id])?.from(wallet_address).send().await?.watch().await?;

        println!("Tx_hash : {tx_hash}");

        Ok(())
    }

    // This function is to relay messages to arbitrum sepolia testnet. So use, arbitrum based config params.
    async fn relay_eth_sep_to_arb_sep_message(&self, message: &Message) -> Result<()> {
        let path = PathBuf::from(&self.config.arb_sep_contract_abi);

        // If you have a hex string with "0x" prefix
        let address_string = &self.config.relayer_public_address;
        let wallet_address = Address::parse_checksummed(address_string, None).expect("Invalid address");
        
        let artifact = std::fs::read(path).expect("Failed to read artifact");
        let json: serde_json::Value = serde_json::from_slice(&artifact)?;

        let abi_value = json.get("abi").expect("Failed to get ABI from artifact");
        let abi = serde_json::from_str(&abi_value.to_string())?;

        let contract = ContractInstance::new(self.config.dest_contract, self.arbitrum_provider.clone(), Interface::new(abi));

        let message_id = DynSolValue::FixedBytes(message.message_id, 32);
        let sender = DynSolValue::Address(message.sender);
        let timestamp = DynSolValue::from(message.timestamp);
        println!("::::: INITATING ARBITRUM CALL :::::");
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
        relayer_private_key: env::var("RELAYER_PRIVATE_KEY")?,
        relayer_public_address: env::var("RELAYER_PUBLIC_ADDRESS")?,
        eth_start_block: env::var("ETH_SEP_START_BLOCK")?.parse()?,
        arb_start_block: env::var("ARB_SEP_START_BLOCK")?.parse()?,
        confirmation_blocks: env::var("CONFIRMATION_BLOCKS")?.parse()?,
        eth_sep_contract_abi: env::var("ETH_SEP_CONTRACT_ABI")?.parse()?,
        arb_sep_contract_abi: env::var("ARB_SEP_CONTRACT_ABI")?.parse()?
    };

    // Create and start the relayer
    let relayer = Arc::new(MessageRelayer::new(config).await?);
    relayer.start().await?;

    // Keep the program running
    tokio::signal::ctrl_c().await?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_eth_sep_to_arb_sep() -> Result<()>{
        // Log { inner: Log { address: 0x3423eebf8d3c03b7109ed9c97f946d209ab45358, data: LogData { topics: [0x4bac9e82130c606f1d88edf9a3046ffd43931f3ef54e0e1feaabbd669757b98f, 0xd9a1b67cff6c44247b8ea7652dc0a3e113820cea9cea7bb5f25a9e3d1b6001d8, 0x000000000000000000000000a014ca018a22f96d00b920410834bb1504b183e1], data: 0x00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000067bc681c00000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000353594e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 } }, block_hash: Some(0xd4090d17efd51c34c2dc57b87d575f1a5498258f1ade68002006e7a8c7214f40), block_number: Some(7775784), block_timestamp: None, transaction_hash: Some(0xef1177a91c35309d13c92a66f1ffaca9b22648fcc105357c5d356fc0dc38b49a), transaction_index: Some(118), log_index: Some(157), removed: false }
        let log = Log {
            inner: ETHLog {
                address: "0x3423eebf8d3c03b7109ed9c97f946d209ab45358".parse().unwrap(),
                data: LogData::new_unchecked(
                    vec![
                        "0x4bac9e82130c606f1d88edf9a3046ffd43931f3ef54e0e1feaabbd669757b98f".parse().unwrap(),
                        "0xd9a1b67cff6c44247b8ea7652dc0a3e113820cea9cea7bb5f25a9e3d1b6001d8".parse().unwrap(),
                        "0x000000000000000000000000a014ca018a22f96d00b920410834bb1504b183e1".parse().unwrap(),
                    ],
                    // Corrected hexadecimal string (even length)
                    "0x00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000067bc681c00000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000353594e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".parse().unwrap(),
                ),
            },
            block_hash: Some("0xd4090d17efd51c34c2dc57b87d575f1a5498258f1ade68002006e7a8c7214f40".parse().unwrap()),
            block_number: Some(7775784 as u64),
            block_timestamp: None,
            transaction_hash: Some("0xef1177a91c35309d13c92a66f1ffaca9b22648fcc105357c5d356fc0dc38b49a".parse().unwrap()),
            transaction_index: Some(118 as u64),
            log_index: Some(157 as u64),
            removed: false,
        };

        let decoded_event = MessageSender::MessageSent::decode_log(&log.inner, false).unwrap();
        let decoded_message = from_utf8(&decoded_event.data.message).unwrap();
        let decoded_message_id = &decoded_event.data.messageId;
        let decoded_message_address = &decoded_event.data.sender;
        let decoded_message_timestamp = &decoded_event.data.timestamp;

        println!("new format: {:?}", &decoded_message);
        
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
            relayer_private_key: env::var("RELAYER_PRIVATE_KEY")?,
            relayer_public_address: env::var("RELAYER_PUBLIC_ADDRESS")?,
            eth_start_block: env::var("ETH_SEP_START_BLOCK")?.parse()?,
            arb_start_block: env::var("ARB_SEP_START_BLOCK")?.parse()?,
            confirmation_blocks: env::var("CONFIRMATION_BLOCKS")?.parse()?,
            eth_sep_contract_abi: env::var("ETH_SEP_CONTRACT_ABI")?.parse()?,
            arb_sep_contract_abi: env::var("ARB_SEP_CONTRACT_ABI")?.parse()?
        };

        // Create and start the relayer
        let relayer = MessageRelayer::new(config).await?;

        let message: Message = Message {
            message_id: *decoded_message_id,
            sender: *decoded_message_address,
            message: decoded_message.to_string(),
            timestamp: *decoded_message_timestamp
        };

        relayer.relay_eth_sep_to_arb_sep_message(&message).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_arb_sep_to_eth_sep() -> Result<()> {
        // Log { inner: Log { address: 0x1b6c07cd43d5a6ea384ec90dccbf8d284964c7f7, data: LogData { topics: [0xfbe5334ea625e76d101c05d3a8561b00ba7037610c6e918747d242d688c25a8d, 0x63525a3736000000000000000000000000000000000000000000000000000000, 0x000000000000000000000000f795d1aca368281ca13a98bfd0cc05d42426ef05], data: 0x00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000067bb6399000000000000000000000000000000000000000000000000000000000000000341434b0000000000000000000000000000000000000000000000000000000000 } }, block_hash: Some(0x25199e1d4849db669331992577d22417d13812ab4ab1dae0251819cf1e7e7292), block_number: Some(126617249), block_timestamp: None, transaction_hash: Some(0xcbda75f2fbfca52b1f41afcca56b1631620784c03295a2afddc1d50a25bc0de6), transaction_index: Some(2), log_index: Some(1), removed: false }
        let log = Log {
            inner: ETHLog {
                address: "0x1b6c07cd43d5a6ea384ec90dccbf8d284964c7f7".parse().unwrap(),
                data: LogData::new_unchecked(
                    vec![
                        "0xfbe5334ea625e76d101c05d3a8561b00ba7037610c6e918747d242d688c25a8d".parse().unwrap(),
                        "0x63525a3736000000000000000000000000000000000000000000000000000000".parse().unwrap(),
                        "0x000000000000000000000000f795d1aca368281ca13a98bfd0cc05d42426ef05".parse().unwrap(),
                    ],
                    // Corrected hexadecimal string (even length)
                    "0x00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000067bb6399000000000000000000000000000000000000000000000000000000000000000341434b0000000000000000000000000000000000000000000000000000000000".parse().unwrap(),
                ),
            },
            block_hash: Some("0x25199e1d4849db669331992577d22417d13812ab4ab1dae0251819cf1e7e7292".parse().unwrap()),
            block_number: Some(126617249 as u64),
            block_timestamp: None,
            transaction_hash: Some("0xcbda75f2fbfca52b1f41afcca56b1631620784c03295a2afddc1d50a25bc0de6".parse().unwrap()),
            transaction_index: Some(2 as u64),
            log_index: Some(1 as u64),
            removed: false,
        };

        let decoded_event = MessageReceived::decode_log(&log.inner, false).unwrap();
        let decoded_message = from_utf8(&decoded_event.data.message).unwrap();
        let decoded_message_id = &decoded_event.data.messageId;
        let decoded_message_address = &decoded_event.data.sender;
        let decoded_message_timestamp = &decoded_event.data.timestamp;

        println!("new format: {:?}", &decoded_message);

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
            relayer_private_key: env::var("RELAYER_PRIVATE_KEY")?,
            relayer_public_address: env::var("RELAYER_PUBLIC_ADDRESS")?,
            eth_start_block: env::var("ETH_SEP_START_BLOCK")?.parse()?,
            arb_start_block: env::var("ARB_SEP_START_BLOCK")?.parse()?,
            confirmation_blocks: env::var("CONFIRMATION_BLOCKS")?.parse()?,
            eth_sep_contract_abi: env::var("ETH_SEP_CONTRACT_ABI")?.parse()?,
            arb_sep_contract_abi: env::var("ARB_SEP_CONTRACT_ABI")?.parse()?
        };

        // Create and start the relayer
        let relayer = MessageRelayer::new(config).await?;

        let message: Message = Message {
            message_id: *decoded_message_id,
            sender: *decoded_message_address,
            message: decoded_message.to_string(),
            timestamp: *decoded_message_timestamp
        };

        relayer.relay_arb_sep_to_eth_sep_message(&message).await?;

        Ok(())
    }
}