use crate::address::Address;
use bitcoinsuite_chronik_client::ChronikClient;
use bitcoinsuite_chronik_client::ScriptType;
use bitcoinsuite_chronik_client::proto::{ScriptUtxos};
use bitcoinsuite_chronik_client::proto::Tx as ProtoTx;
use bitcoinsuite_core::Sha256d;
use bitcoinsuite_core::Hashed;
use crate::address::AddressType;
use crate::incomplete_tx::{IncompleteTx, Utxo, Output};
use crate::tx::{Tx, TxOutpoint};
use crate::outputs::{P2PKHOutput};
use crate::outputs;
use crate::outputs::SLPSendOutput;
use std::collections::HashSet;
use std::collections::HashMap;
use std::error::Error;
use std::io::{self, Write};
use rand::thread_rng;
use reqwest::Client as ReqwestClient; 
use rand::RngCore;
use secp256k1::{Secp256k1, PublicKey, SecretKey};
use num_format::{Locale, ToFormattedString};
use text_io::{read};
use hex;


pub struct Wallet {
    secret_key: secp256k1::SecretKey,
    address: Address,
    chronik_client: ChronikClient, 
}

struct TokenInfo {
    token_symbol: String,
    token_name: String,
    decimals: u32,
    amount: f64,
    token_id_hex: String,
}



impl Wallet {
    pub fn from_secret(secret: &[u8]) -> Result<Wallet, Box<dyn std::error::Error>> {
        let secret_key = secp256k1::SecretKey::from_slice(&secret)?;
        let curve = secp256k1::Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&curve, &secret_key);
        let addr = Address::from_pub_key("ergon", &pk);
        let chronik_url = "https://chronik.be.cash/xrg";
        let chronik_client = ChronikClient::new(chronik_url.to_string())?;


        Ok(Wallet {
            secret_key,
            address: addr,
            chronik_client, 
        })
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn get_new_address(&self) -> Result<(Address, SecretKey), secp256k1::Error> {
        let secp = Secp256k1::new();
        let mut rng = thread_rng();
        
        // Generate a random 32-byte array
        let mut secret_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_key_bytes);
    
        // Create a secret key from the random bytes
        let secret_key = SecretKey::from_slice(&secret_key_bytes)
            .expect("32 bytes, within curve order, can't fail");
    
        // Derive the public key from the secret key
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    
        // Create an address from the public key
        let address = Address::from_pub_key("ergon", &public_key);
    
        Ok((address, secret_key))
    }

    #[allow(unreachable_patterns)]
    pub async fn get_utxos(&self, address: &Address) -> Result<Vec<bitcoinsuite_chronik_client::proto::Utxo>, Box<dyn Error>> {
   
        let address_bytes = address.bytes();
        //println!("Address Bytes: {:?}", address_bytes);
        let script_type = match address.addr_type() {
            AddressType::P2PKH => ScriptType::P2pkh,
            AddressType::P2SH => ScriptType::P2sh,
            _ => return Err("Unsupported address type".into()),
        };
        let script_payload = hex::encode(&address_bytes);
        //println!("Payload Used: {:?}", script_payload);
        let script_endpoint = format!("script/{}/{}/utxos", script_type, script_payload);
        //println!("script_endpoint: {:?}", script_endpoint);
        // Create a reqwest client
        let client = ReqwestClient::new();
        let chronik_url = "https://chronik.be.cash/xrg";
        // Concatenate the base URL and the script endpoint to form the complete URL
        let full_url = format!("{}/{}", chronik_url, script_endpoint);
        //println!("full_url: {:?}", full_url);
        // Make a GET request to the complete URL
        let response = client.get(&full_url).send().await?;
        //println!("response: {:?}", response);
        // Check if the response status code is 200 OK
        if response.status() != reqwest::StatusCode::OK {
            return Err(format!("Error: {}", response.status()).into());
        }
        // Parse the response body as bytes
        let response_bytes = response.bytes().await?;
        //println!("response_bytes: {:?}", response_bytes);
        // Deserialize the response bytes into ScriptUtxos
        let utxos_response: ScriptUtxos = prost::Message::decode(&response_bytes[..])?;
        //println!("utxos_response: {:?}", utxos_response);
        // Access the serialized script
        let script_bytes: &[u8] = &utxos_response.output_script;
        //println!("script_bytes: {:?}", script_bytes);
        // Deserialize the byte array into a ScriptUtxos message
        let script_utxos: ScriptUtxos = prost::Message::decode(script_bytes).unwrap();
        //println!("script_utxos: {:?}", script_utxos);
        // Access the list of ScriptUtxo messages from script_utxos
        let mut utxos: Vec<bitcoinsuite_chronik_client::proto::Utxo> = script_utxos.utxos;
        //println!("utxos: {:?}", utxos);

        // Sort the UTXOs so that SLP UTXOs come first
        utxos.sort_by(|a, b| {
            let a_is_slp = a.slp_token.is_some();
            let b_is_slp = b.slp_token.is_some();
            b_is_slp.cmp(&a_is_slp) // This will put SLP UTXOs before non-SLP UTXOs
        });


        Ok(utxos)
    }
    
    
    pub async fn get_balance(&self) -> Result<(), Box<dyn std::error::Error>> {
        let utxos = self.get_utxos(&self.address).await?;
        //println!("Balance Utxos: {:#?}", utxos);
    
        let mut xrg_balance = 0u64;
        let mut token_balances: HashMap<Vec<u8>, u64> = HashMap::new();
    
        for utxo in utxos.iter() {
            match (&utxo.slp_meta, &utxo.slp_token) {
                (Some(slp_meta), Some(slp_token)) => {
                    *token_balances.entry(slp_meta.token_id.clone()).or_insert(0) += slp_token.amount;
                },
                _ => {
                    xrg_balance += utxo.value as u64;
                },
            }
        }
    
        println!("Wallet Balance Summary");
        println!("----------------------");
        println!("XRG Balance: {} ergoshis (≈ {:0.8} ⵟ )", 
                 xrg_balance.to_formatted_string(&Locale::en), 
                 xrg_balance as f64 / 1_000_000_000_f64);
    
        println!("--------------");    
        for (token_id, amount) in token_balances {
            let token_id_hash = Sha256d::from_slice(&token_id)?;
            let byte_slice = token_id_hash.as_ref();
            let mut token_id_bytes = byte_slice.to_vec();
            token_id_bytes.reverse();
            let reversed_token_id_hash = Sha256d::from_slice(&token_id_bytes)?;
            let token_info = self.fetch_token(&reversed_token_id_hash).await?;
        
            if let Some(slp_tx_data) = &token_info.slp_tx_data {

                println!("\nTokens:");
                println!("-------"); 
                if let Some(genesis_info) = &slp_tx_data.genesis_info {
                    let token_symbol = String::from_utf8(genesis_info.token_ticker.clone()).unwrap_or_default();
                    let token_name = String::from_utf8(genesis_info.token_name.clone()).unwrap_or_default();
                    let decimals = genesis_info.decimals as u32;
                    let full_unit_amount = amount as f64 / 10f64.powi(decimals as i32);
        
                    println!("{:20} {:20}", "Token Name:", token_name);
                    println!("{:20} {:.8} {}", "Amount:", full_unit_amount, token_symbol); // Symbol follows the amount
                    println!("{:20} {:20}\n",
                             "Token ID (Hex):", hex::encode(token_id));
                    println!("-------");    

                }
            }
        }
        
        Ok(())
        
    }
    
    
    pub async fn get_transaction_details(&self, txid: &Sha256d) -> Result<ProtoTx, Box<dyn Error>> {
        let transaction_details = self.chronik_client.tx(txid).await?;
        //println!("Transaction Details: {:?}", transaction_details);
        Ok(transaction_details)
    }

    pub async fn fetch_token(&self, token_id: &Sha256d) -> Result<bitcoinsuite_chronik_client::proto::Token, Box<dyn std::error::Error>> {
        let token_info = self.chronik_client.token(token_id).await?;
        //println!("Token Info: {:#?}", token_info);
        Ok(token_info)
    }

    pub async fn wait_for_transaction(
        &self, 
        address: &Address, 
        already_existing: &HashSet<Vec<u8>>) -> Result<bitcoinsuite_chronik_client::proto::Utxo, Box<dyn std::error::Error>> 
    {
        loop {
            let utxos = self.get_utxos(address).await?;
            let mut remaining = utxos.into_iter()
                .filter(|utxo| {
                    if let Some(ref outpoint) = utxo.outpoint {
                        !already_existing.contains(&outpoint.txid)
                    } else {
                        false
                    }
                })
                .collect::<Vec<_>>();
            if !remaining.is_empty() {
                return Ok(remaining.remove(0));
            }
            tokio::time::sleep(std::time::Duration::new(1, 0)).await;
        }
    }
    
    pub async fn init_transaction(&self, temp_address: Option<Address>, temp_secret_key: Option<SecretKey>, selected_token_id: Option<Vec<u8>>) -> Result<(IncompleteTx, u64, u64), Box<dyn std::error::Error>> {
        let address_to_use = temp_address.unwrap_or_else(|| self.address.clone());
        let key_to_use = temp_secret_key.unwrap_or_else(|| self.secret_key.clone());
    
        let mut tx_build = IncompleteTx::new_simple();
        let mut balance = 0;
        let mut balance_token = 0;
    
        let utxos = self.get_utxos(&address_to_use).await?;
    
        for utxo in utxos.iter() {
            let is_slp_utxo = utxo.slp_token.is_some();
            let matches_selected_token = selected_token_id.as_ref().map_or(false, |token_id| {
                utxo.slp_meta.as_ref().map_or(false, |slp_meta| slp_meta.token_id == *token_id)
            });

            // Filter out non-SLP UTXOs with SLP metadata and output idx of 1 or 2 only when a token ID is given
            if selected_token_id.is_some() && utxo.slp_meta.is_some() && !is_slp_utxo && (utxo.outpoint.as_ref().map_or(false, |outpoint| outpoint.out_idx == 1 || outpoint.out_idx == 2)) {
                continue;
            }
    
            // Add non-SLP UTXOs or SLP UTXOs that match the selected token ID
            if !is_slp_utxo || matches_selected_token {
                balance += utxo.value as u64;
    
                if matches_selected_token {
                    if let Some(slp_token) = &utxo.slp_token {
                        balance_token += slp_token.amount;
                    }
                }
    
                let tx_hash_bytes = match utxo.outpoint.as_ref() {
                    Some(outpoint) => outpoint.txid.clone(),
                    None => return Err("Outpoint is None".into()),
                };
    
                let tx_hash_array = if tx_hash_bytes.len() == 32 {
                    let mut array = [0u8; 32];
                    array.copy_from_slice(&tx_hash_bytes);
                    array
                } else {
                    return Err("Invalid tx_hash_bytes length".into());
                };
    
                let output_idx = match utxo.outpoint.as_ref() {
                    Some(outpoint) => outpoint.out_idx,
                    None => return Err("Outpoint is None".into()),
                };

                tx_build.add_utxo(Utxo {
                    key: key_to_use.clone(),
                    output: Box::new(P2PKHOutput {
                        address: address_to_use.clone(),
                        value: utxo.value as u64,
                    }),
                    outpoint: TxOutpoint {
                        tx_hash: tx_hash_array,
                        output_idx: output_idx,
                    },
                    sequence: 0xffff_ffff,
                });
            }
        }
    
        Ok((tx_build, balance, balance_token))
    }

            

    pub async fn get_balance_and_select_asset(&self) -> Result<(), Box<dyn std::error::Error>> {
        let utxos = self.get_utxos(&self.address).await?;
        //println!("Balance Utxos: {:#?}", utxos);
    
        let mut xrg_balance = 0u64;
        let mut token_balances: HashMap<Vec<u8>, u64> = HashMap::new();
    
        for utxo in utxos.iter() {
            match (&utxo.slp_meta, &utxo.slp_token) {
                (Some(slp_meta), Some(slp_token)) => {
                    *token_balances.entry(slp_meta.token_id.clone()).or_insert(0) += slp_token.amount;
                },
                _ => {
                    xrg_balance += utxo.value as u64;
                },
            }
        }
    
        println!("Wallet Balance Summary");
        println!("----------------------");
        println!("XRG Balance: {} ergoshis (≈ {:0.8} ⵟ )", 
                xrg_balance.to_formatted_string(&Locale::en), 
                xrg_balance as f64 / 1_000_000_000_f64);

        println!("--------------"); 

        
        let mut token_info_vector: Vec<TokenInfo> = Vec::new();
   
        for (token_id, amount) in &token_balances {
            let token_id_hash = Sha256d::from_slice(&token_id)?;
            let byte_slice = token_id_hash.as_ref();
            let mut token_id_bytes = byte_slice.to_vec();
            token_id_bytes.reverse();
            let reversed_token_id_hash = Sha256d::from_slice(&token_id_bytes)?;
            let token_info = self.fetch_token(&reversed_token_id_hash).await?;
            //println!("Token Info: {:#?}", token_info);

            if let Some(slp_tx_data) = &token_info.slp_tx_data {

                println!("\nTokens:");
                println!("-------"); 
                if let Some(genesis_info) = &slp_tx_data.genesis_info {
                    let token_symbol = String::from_utf8(genesis_info.token_ticker.clone()).unwrap_or_default();
                    let token_name = String::from_utf8(genesis_info.token_name.clone()).unwrap_or_default();
                    let decimals = genesis_info.decimals as u32;
                    let full_unit_amount = *amount as f64 / 10f64.powi(decimals as i32);
                    let token_id_hex = hex::encode(token_id);
        
                    let token_info = TokenInfo {
                        token_symbol: token_symbol.clone(),
                        token_name: token_name.clone(),
                        decimals,
                        amount: full_unit_amount,
                        token_id_hex,
                    };
        
                    token_info_vector.push(token_info);
        
        
                    println!("{:20} {:20}", "Token Name:", token_name.clone());
                    println!("{:20} {:.8} {}", "Amount:", full_unit_amount, token_symbol.clone()); // Symbol follows the amount
                    println!("{:20} {:20}\n",
                            "Token ID (Hex):", hex::encode(token_id));
                    println!("-------");    
                }
            }
        }
        let mut assets: Vec<String> = Vec::new();
        assets.push("XRG".to_string()); // Add XRG as the first asset
        
        for token_info in &token_info_vector {
            assets.push(token_info.token_symbol.clone());
        }
        
        // Display assets with numbers
        for (index, asset) in assets.iter().enumerate() {
            println!("{}: {} Balance", index, asset);
        }
        
        // Ask user to select an asset
        print!("Enter the number of the asset you want to send: ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let selected_index = input.trim().parse::<usize>()?;
    
        if selected_index == 0 {
            let (mut tx_build, balance, _balance_token) = self.init_transaction(None, None, None).await?;
            println!("Your wallet's balance is: {} ergoshis or {} ⵟ.",
                    balance,
                    balance as f64 / 100_000_000.0);
            if balance < self.dust_amount() {
                println!("Your balance ({}) isn't sufficient to broadcast a transaction. Please fund some \
                        XRG to your wallet's address: {}", balance, self.address().cash_addr());
                return Ok(());
            }
            print!("Enter the address to send to: ");
            io::stdout().flush()?;
            let addr_str: String = read!("{}\n");
            let addr_str = addr_str.trim();
            let receiving_addr = match Address::from_cash_addr(addr_str.to_string())  {
                Ok(addr) => addr,
                Err(err) => {
                    println!("Please enter a valid address: {:?}", err);
                    return Ok(());
                }
            };
            if receiving_addr.prefix() == "simpleledger" {
                println!("Note: You entered a Simple Ledger Protocol (SLP) address, but this wallet only \
                        contains ordinary non-token XRG. The program will proceed anyways.");
            }
            print!("Enter the amount in ergoshis to send, or \"all\" (without quotes) to send the entire \
                    balance: ");
            io::stdout().flush()?;
            let send_amount_str: String = read!("{}\n");
            let send_amount_str = send_amount_str.trim();
            let send_amount = if send_amount_str == "all" {
                balance
            } else {
                send_amount_str.parse::<u64>()?
            };
            let mut output_send = outputs::P2PKHOutput {
                value: send_amount,
                address: receiving_addr,
            };
            let send_idx = tx_build.add_output(&output_send);
            let mut output_back_to_wallet = outputs::P2PKHOutput {
                value: 0,
                address: self.address().clone(),
            };
            let back_to_wallet_idx = tx_build.add_output(&output_back_to_wallet);
            let send_back_to_wallet_amount = if balance < send_amount + 10 {
                output_send.value = balance - 10;
                tx_build.replace_output(send_idx, &output_send);
                0
            } else {
                balance - (send_amount + 10)
            };
            if send_back_to_wallet_amount < self.dust_amount() {
                tx_build.remove_output(back_to_wallet_idx);
            } else {
                output_back_to_wallet.value = send_back_to_wallet_amount;
                tx_build.replace_output(back_to_wallet_idx, &output_back_to_wallet);
            }
            //println!("Output back value : {:?}", output_back_to_wallet.value);
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            let tx = tx_build.sign();
            //println!("Transaction hex : {:?}", tx);
            let response = self.send_tx(&tx).await?; // Use await here
            println!("Sent transaction. Transaction ID is: {}", response);
        
            Ok(())
        
        } else if let Some(selected_token_info) = token_info_vector.get(selected_index - 1) {
            let selected_token_symbol = &selected_token_info.token_symbol;
            let selected_token_id_hex = &selected_token_info.token_id_hex;
            let selected_token_id_decimals = selected_token_info.decimals;
            let _selected_token_id_amount = selected_token_info.amount;
    
            // Convert the hex string to Vec<u8>
            let token_id_vec = hex::decode(selected_token_id_hex)
                .map_err(|e| format!("Failed to decode hex: {}", e))?;

            // Now pass it as an Option<Vec<u8>>
            let (mut token_tx_build, balance, balance_token) = self.init_transaction(None, None, Some(token_id_vec)).await?;
                        
            println!("Your wallet's XRG balance is: {} ergoshis or {} ⵟ.",
                    balance,
                    balance as f64 / 100_000_000.0);
            if balance < self.dust_amount() {
                println!("Your balance ({}) isn't sufficient to broadcast a transaction. Please fund some \
                        XRG to your wallet's address: {}", balance, self.address().cash_addr());
                return Ok(());
            }


            let balance_token_display = balance_token as f64 / 10f64.powi(selected_token_id_decimals as i32);

            println!("Your wallet's balance is: {} {}", 
                balance_token_display,
                selected_token_symbol, 
                );
        
            print!("Enter the address to send to: ");
            io::stdout().flush()?;
            let addr_str: String = read!("{}\n");
            let addr_str = addr_str.trim();
            let receiving_addr = match Address::from_cash_addr(addr_str.to_string())  {
                Ok(addr) => addr,
                Err(err) => {
                    println!("Please enter a valid address: {:?}", err);
                    return Ok(());
                }
            };
            if receiving_addr.prefix() == "simpleledger" {
                println!("Note: You entered a Simple Ledger Protocol (SLP) address, but this wallet only \
                        contains ordinary non-token XRG. The program will proceed anyways.");
            }
            // Initialize transaction with SLP output
            print!("Enter the amount to send, or \"all\" (without quotes) to send the entire balance: ");
            io::stdout().flush()?;
            let send_amount_str: String = read!("{}\n");
            let send_amount_str = send_amount_str.trim();
            //println!("Send amount string: {:?}", send_amount_str);
            //println!("Selected token decimal: {:?}", selected_token_id_decimals);
            
            let send_amount_sats: u64 = if send_amount_str == "all" {
                // If "all", use the entire token balance in sats
                balance_token
            } else {
                // If a specific amount is entered, parse it and convert to sats
                match send_amount_str.parse::<f64>() {
                    Ok(amount) => {
                        // Convert the entered amount to sats using token decimals
                        (amount * 10f64.powi(selected_token_id_decimals as i32)) as u64
                    }
                    Err(_) => {
                        println!("Invalid amount entered.");
                        return Ok(());
                    }
                }
            };
            
            //println!("Send amount in sats: {:?}", send_amount_sats);

            let token_id_vec = hex::decode(&selected_token_info.token_id_hex)?;            
            let token_change = balance_token - send_amount_sats;

            // Construct the output_quantities vector
            let output_quantities = vec![
                send_amount_sats,
                token_change,
            ];

            // Declare output_slp outside the if block
            let mut output_slp: Option<SLPSendOutput> = None;

            if token_id_vec.len() == 32 {
                let mut token_id_arr = [0u8; 32];
                token_id_arr.copy_from_slice(&token_id_vec);
                output_slp = Some(SLPSendOutput {
                    token_type: 1,
                    token_id: token_id_arr,
                    output_quantities,
                });
            } else {
                // Handle error: token_id_vec is not of length 32
                return Err("Token ID must be 32 bytes long".into());
            }

            // Use output_slp after checking it's Some
            if let Some(slp_output) = output_slp {
                token_tx_build.add_output(&slp_output);

                let output_send = outputs::P2PKHOutput {
                    value: 5,
                    address: receiving_addr,
                };

                token_tx_build.add_output(&output_send);

                let output_token_change = outputs::P2PKHOutput {
                    value: 5,
                    address: self.address().clone(),
                };

                token_tx_build.add_output(&output_token_change);

                let mut output_back_to_wallet = outputs::P2PKHOutput {
                    value: 0,
                    address: self.address().clone(),
                };
                let back_to_wallet_idx = token_tx_build.add_output(&output_back_to_wallet);

                let fee = 10;
                let total_spent = slp_output.value() +
                                output_send.value() +
                                output_token_change.value() +
                                fee;
            
                output_back_to_wallet.value = balance - total_spent;
                token_tx_build.replace_output(back_to_wallet_idx, &output_back_to_wallet);
                let token_tx = token_tx_build.sign();
                let response = self.send_tx(&token_tx).await?; // Use await here
                println!("Sent transaction. Transaction ID is: {}", response);
                
                Ok(())
            } else {
                // Handle the case where output_slp is None (optional)
                // You can either return an error or perform other actions.
                // For example, you can return an error like this:
                return Err("Output slp is None".into());
            }
                
        } else {
             // Handle the case where the selected_index is invalid here
            println!("Invalid selection.");
            Ok(())
        }
    }
    
    pub async fn send_tx(&self, tx: &Tx) -> Result<String, Box<dyn std::error::Error>> {
        // Serialize the transaction
        let mut tx_ser = Vec::new();
        tx.write_to_stream(&mut tx_ser)?;

    
        // Encode the serialized transaction in hexadecimal format
        let tx_hex = hex::encode(&tx_ser);
        //println!("Raw tx: {:?}", tx_hex);

    
        // Prepare the request payload for Chronik
        let raw_tx = hex::decode(&tx_hex).map_err(|e| e.to_string())?;

    
        // Use the ChronikClient associated with the Wallet to broadcast the transaction
        let response = self.chronik_client.broadcast_tx(raw_tx).await?;
    
        // Extract the transaction ID from the Chronik response
        let txid = response.txid;
        // Reverse the bytes in place
        let mut txid_rev = txid.clone();
        txid_rev.reverse();

        // Now encode the reversed bytes
        let txid_hex = hex::encode(txid_rev);

        Ok(txid_hex)

    }
    
    pub fn dust_amount(&self) -> u64 {
        5
    }
}
