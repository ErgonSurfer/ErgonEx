use crate::wallet::Wallet;
use bitcoinsuite_core::{Sha256d, Hashed};
use crate::outputs::{EnforceOutputsOutput, SLPSendOutput, P2PKHOutput, TradeOfferOutput, P2SHOutput};
use crate::address::{Address, AddressType, to_cash_addr};
use crate::hash::hash160;
use crate::incomplete_tx::{IncompleteTx, Output, Utxo};
use crate::tx::{tx_hex_to_hash, TxOutpoint};
use crate::exch::EXCH;
use std::io::{self, Write};
use text_io::{read};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use futures::stream::{self, StreamExt};
use std::cmp::Ordering;
use tokio::time::{sleep, Duration};
use colored::*;





#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct TokenEntry {
    id: String,
    timestamp: String,
    symbol: Option<String>,
    name: Option<String>,
    #[serde(alias = "documentUri")]
    document_uri: Option<String>,
    #[serde(alias = "documentHash")]
    document_hash: Option<String>,
    decimals: u64,
    #[serde(alias = "initialTokenQty")]
    initial_token_qty: f64,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct ValidTrade {
    txid: String,
    valid: bool,
    token_id: String,
    token_value: u64, 
}




async fn fetch_tokens(ids: &[&str]) -> Result<Vec<TokenEntry>, Box<dyn std::error::Error>> {
    let ids: Vec<String> = ids.iter().map(|&id| id.to_string()).collect();
    let query: Vec<_> = ids.iter().map(|id| ("tokenIds", id)).collect();
    let url = reqwest::Url::parse_with_params("https://api.calory.money/tokens", &query)?;
    let response = reqwest::get(url).await?.text().await?;

    // Deserialize the JSON into Vec<TokenEntry>
    let mut tokens: Vec<TokenEntry> = serde_json::from_str(&response)?;

    // Removing duplicates from tokens vector
    tokens.sort_by(|a, b| a.id.cmp(&b.id));
    tokens.dedup_by(|a, b| a.id == b.id);

    Ok(tokens)
    }

fn option_str(s: &Option<String>) -> &str {
    s.as_ref().map(|x| x.as_str()).unwrap_or("<empty>")
}

pub async fn create_trade_interactive(wallet: &Wallet) -> Result<(), Box<dyn std::error::Error>> {
    let (tx_build, balance, _balance_token) = wallet.init_transaction(None, None, None).await?;
    if balance < 1000 {
        println!("{}", format!("Your balance ({}) is too low.", balance).red());
        println!("{}", "You need at least 1000 ergoshis to access trading.".red());
        println!("Please fund some XRG to your wallet's address: {}", wallet.address().cash_addr().yellow());                  
        return Ok(());
    }
    println!("{}", "Enter the symbol of the token you want to sell:".bright_white());
    io::stdout().flush()?;
    let token_str: String = read!("{}\n");
    let token_str = token_str.trim().to_string();

    let mut tokens_found = fetch_tokens(&[&token_str]).await?;
    if tokens_found.len() == 0 {
        let all_tokens = fetch_tokens(&[]).await?; // If you want to fetch all tokens without a specific ID
        let mut tokens_found_name = all_tokens.into_iter().filter(|token| {
            token.name.as_ref() == Some(&token_str) || token.symbol.as_ref() == Some(&token_str)
        }).collect::<Vec<_>>();
        if tokens_found_name.len() == 0 {
            println!("Didn't find any tokens with id/name/hash '{}'.", token_str);
            return Ok(())
        }
        tokens_found.append(&mut tokens_found_name);
    }
    let token = if tokens_found.len() == 1 {
        tokens_found.remove(0)
    } else {
        println!("Found multiple tokens with those criteria: ");
        println!(
            "{:3} {:64} {:>12} {:20} {}",
            "#",
            "ID",
            "Symbol",
            "Name",
            "Uri",
        );
        for (i, token) in tokens_found.iter().enumerate() {
            println!(
                "{:3} {:64} {:>12} {:20} {}",
                i,
                token.id,
                option_str(&token.symbol),
                option_str(&token.name),
                option_str(&token.document_uri),
            );
        }
        print!("Enter the number (0-{}) you want to sell: ", tokens_found.len() - 1);
        io::stdout().flush()?;
        let token_idx_str: String = read!("{}\n");
        let token_idx_str = token_idx_str.trim();
        if token_idx_str.len() == 0 {
            return Ok(());
        }
        match token_idx_str.parse::<usize>() {
            Ok(token_idx) => if tokens_found.len() > token_idx {
                tokens_found.remove(token_idx)
            } else {
                println!("Index {} not in the list. Exit.", token_idx);
                return Ok(())
            },
            Err(err) => {
                println!("Invalid number: {}", err);
                println!("Exit.");
                return Ok(())
            }
        }
    };
    println!("{}", "Selected token:".bright_white().bold());
    println!("{:>18} {}", "ID:".bright_white(), token.id.to_string().bright_yellow());
    println!("{:>18} {}", "Timestamp:".bright_white(), token.timestamp.to_string().bright_yellow());
    println!("{:>18} {}", "Symbol:".bright_white(), option_str(&token.symbol).bright_yellow());
    println!("{:>18} {}", "Name:".bright_white(), option_str(&token.name).bright_yellow());
    println!("{:>18} {}", "Document URI:".bright_white(), option_str(&token.document_uri).bright_yellow());
    println!("{:>18} {}", "Document Hash:".bright_white(), option_str(&token.document_hash).bright_yellow());
    println!("{:>18} {}", "Decimals:".bright_white(), token.decimals.to_string().bright_yellow());
    println!("{:>18} {}", "Initial Token Qty:".bright_white(), token.initial_token_qty.to_string().bright_yellow());
    
    print!(
        "Enter the amount of {} you want to sell: ",
        option_str(&token.symbol).bright_magenta()
    );
    io::stdout().flush()?;
    let sell_amount_str: String = read!("{}\n");
    let sell_amount_str = sell_amount_str.trim();
    let sell_amount_display: f64 = sell_amount_str.parse().map_err(|err: std::num::ParseFloatError| {
        println!("{}", "Invalid number:".red().bold());
        println!("Error: {}", err.to_string().red());
        println!("Exit.");
        err
    })?;
    let sell_amount = (sell_amount_display * (10.0f64).powi(token.decimals as i32)) as u64;


    // Prompt for buy amount
    print!("Enter the amount of {} you want to receive (1 ergoshi = 0.00000001 ⵟ): ", "ergoshis".bright_cyan());
    io::stdout().flush()?;
    let buy_amount_str: String = read!("{}\n");
    let buy_amount_str = buy_amount_str.trim();
    let buy_amount: u64 = buy_amount_str.parse().map_err(|err: std::num::ParseIntError| {
        println!("{}", "Invalid number:".red().bold());
        println!("Error: {}", err.to_string().red());
        println!("Exit.");
        err
    })?;
    
    if buy_amount < 5 {
        println!("{}", "The minimum allowed amount is 5 ergoshis.".red().bold());
        println!("Please retry with a valid amount.");
        return Ok(());
    }

    confirm_trade_interactive(wallet,
                              tx_build,
                              balance,
                              &token,
                              sell_amount,
                              sell_amount_display,
                              buy_amount).await?;

    Ok(())
}

async fn confirm_trade_interactive(wallet: &Wallet,
                             _tx_build: IncompleteTx,
                             _balance: u64,
                             token: &TokenEntry,
                             sell_amount: u64,
                             sell_amount_display: f64,
                             buy_amount: u64) -> Result<(), Box<dyn std::error::Error>> {
    let mut token_id = [0; 32];
    token_id.copy_from_slice(&hex::decode(&token.id)?);
    let receiving_address = wallet.address().clone();
    let cancel_address = wallet.address().clone();
    let signal_address_str = "ergon:qph2jxmrk2uswgvfdjeld32hrxjpxz8nyyy248su37";
    let signal_address = Address::from_cash_addr(signal_address_str.to_string())
        .expect("Invalid address"); // Handle this error appropriately
    let (temp_address, temp_secret_key) = wallet.get_new_address()?;

    let already_existing = wallet.get_utxos(&temp_address).await?
    .iter()
    .map(|utxo| {
        if let Some(ref outpoint) = utxo.outpoint {
            outpoint.txid.clone()
        } else {
            // Handle the case where outpoint is None, possibly with an error or a default value
            Vec::new() // Assuming txid is a Vec<u8>, adjust accordingly
        }
    })
    .collect::<HashSet<_>>();

    println!("{}", "--------------------------------------------------".bright_blue());
    crate::display_qr::display(temp_address.cash_addr().as_bytes());
    println!("Please send EXACTLY {} {} to the following address:", sell_amount_display.to_string().bright_magenta(), option_str(&token.symbol).bright_magenta());
    println!("{}", temp_address.cash_addr().bright_cyan());
    println!("{}", "You can also scan the QR code above.".bright_white());
    println!("{}", "\nDO NOT CLOSE THIS PROGRAM YET BEFORE OR AFTER YOU SENT THE PAYMENT".bright_red().bold());
    println!("{}", "Sending a different amount or incorrect token may burn the tokens.".red().bold());

    println!("{}", "Waiting for transaction...".bright_white());
    let utxo = wallet.wait_for_transaction(&temp_address, &already_existing).await?;
    let (txid, _output_idx) = if let Some(outpoint) = &utxo.outpoint {
        let mut txid_reversed = outpoint.txid.clone();
        txid_reversed.reverse(); // Reverse the byte order for endianness.
        let txid_hex = hex::encode(txid_reversed); // Convert the reversed bytes to hexadecimal string.
        (txid_hex, outpoint.out_idx)
    } else {
        // Handle the case where outpoint is None
        return Err("utxo outpoint is None".into());
    };
    
    println!("Received tx: {}", txid.bright_green());
    println!("{}", "--------------------------------------------------".bright_blue());
    println!("{}", "Let's be sure you are not about to burn tokens...".bright_yellow());
    sleep(Duration::from_secs(2)).await;

    // Get the UTXOs for temp_address
    let utxos = wallet.get_utxos(&temp_address).await?;
    if utxos.is_empty() {
        return Err("No UTXOs found for temp_address".into());
    }

    //println!("SLP Meta {:?}", utxo.slp_meta);
    //println!("SLP Token {:?}", utxo.slp_token);

    // Assuming you have already fetched the utxo and its outpoint
    let txid = if let Some(outpoint) = &utxo.outpoint {
        let mut txid_array = [0u8; 32];
        if outpoint.txid.len() == 32 {
            txid_array.copy_from_slice(&outpoint.txid);
            Sha256d::new(txid_array)
        } else {
            return Err("Invalid txid length".into());
        }
    } else {
        return Err("utxo outpoint is None".into());
    };
    
    // Get transaction details using the txid
    let transaction_details = wallet.get_transaction_details(&txid).await?;
    //println!("Transaction detail for sender: {:?}", transaction_details);


    // Identify the sender from the transaction inputs
    let sender_address_bytes = if let Some(first_input) = transaction_details.inputs.first() {
        // Extract address bytes from the script public key
        if first_input.output_script.len() == 25 && first_input.output_script.starts_with(&[0x76, 0xa9]) && first_input.output_script[23] == 0x88 && first_input.output_script[24] == 0xac {
            let pkh_slice = &first_input.output_script[3..23]; // Extract PKH slice
            let mut pkh_array = [0u8; 20];
            pkh_array.copy_from_slice(pkh_slice); // Convert to [u8; 20] array
            Some(pkh_array)
        } else {
            None // or handle other script types
        }
    } else {
        return Err("Transaction has no inputs".into());
    };
    
    // Extract the sender's address as a cash address string
    let cash_address = if let Some(pkh) = sender_address_bytes {
        to_cash_addr("ergon", AddressType::P2PKH, &pkh)
    } else {
        return Err("Could not extract sender address from script".into());
    };
    //println!("Sender Cash Address: {}", cash_address);


    println!("{}", "Let's first fund the disposable wallet with some ergoshis for fees".bright_green());

    // Initialize the transaction builder and get the current wallet balance
    let (mut funding_tx_build, balance, _balance_token) = wallet.init_transaction(None, None, None).await?;
    //println!("Balance is: {}", balance);
    let refund_fees = 142;

    // Now sender_address is an Address object
    let fund_output = P2PKHOutput {
        value: refund_fees,
        address: temp_address.clone(),
    };

    let mut output_back_to_wallet = P2PKHOutput {
        value: 0,  // for generating tx size
        address: wallet.address().clone(),
    };

    funding_tx_build.add_output(&fund_output);


    let back_to_wallet_idx = funding_tx_build.add_output(&output_back_to_wallet);

    let fee = 10;
    let total_spent =
            fund_output.value() +
            fee;
            
    

    output_back_to_wallet.value = balance - total_spent;
    funding_tx_build.replace_output(back_to_wallet_idx, &output_back_to_wallet);
    let funding_tx = funding_tx_build.sign();

    let result = wallet.send_tx(&funding_tx).await?;
    println!("Disposable wallet funded with transaction: {}", result);

    let received_amount = utxo.slp_token.as_ref().map(|token| token.amount);

    // Extract received token ID as a Vec<u8> and convert it to a hexadecimal string for comparison
    let received_token_id_str = utxo.slp_meta
        .as_ref()
        .map(|meta| hex::encode(&meta.token_id))
        .unwrap_or_default();

    // The expected token ID (token.id) is already a hexadecimal string
    let expected_token_id_hex = token.id.clone();

    // Now both received_token_id_str and expected_token_id_hex are hexadecimal strings
    if received_token_id_str != expected_token_id_hex || received_amount != Some(sell_amount) {
        println!("Expected token ID: {}, Value: {}", expected_token_id_hex, sell_amount);
        println!("Received token ID: {}, Value: {:?}", received_token_id_str, received_amount);

        // Proceed with the refund process
        println!("Token ID or value does not match. Preparing to refund the transaction on wallet {} to save your funds", cash_address);
        println!("Let's send back the tokens to their owner");
        let received_token_id_bytes = hex::decode(received_token_id_str.clone())
            .map_err(|e| format!("Failed to decode hex: {}", e))?;

        let (mut refund_tx_build, balance, _balance_token) = wallet
            .init_transaction(Some(temp_address.clone()), Some(temp_secret_key), Some(received_token_id_bytes))
            .await?;
    

        let mut token_id = [0; 32];
        token_id.copy_from_slice(&hex::decode(&received_token_id_str)?);
        
        let output_slp = SLPSendOutput {
            token_type: 1,
            token_id,
            output_quantities: match received_amount {
                Some(amount) => vec![amount, 0],
                None => {
                    return Err("Received amount is None".into());
                }
            },
        };
        

        // Convert the sender address from String to Address
        let sender_address = match Address::from_cash_addr(cash_address.clone()) {
            Ok(addr) => addr,
            Err(_) => return Err("Invalid sender address".into()),
        };

        let mut output_back_to_wallet = P2PKHOutput {
            value: 0,  // for generating tx size
            address: temp_address.clone(),
        };

        // Now sender_address is an Address object
        let send_output = P2PKHOutput {
            value: 5,
            address: sender_address,
        };
        refund_tx_build.add_output(&output_slp);
        refund_tx_build.add_output(&send_output);

        let back_to_wallet_idx = refund_tx_build.add_output(&output_back_to_wallet);

        let fee = 10;
        let total_spent =
            output_slp.value() +
                send_output.value() +
                fee;

        output_back_to_wallet.value = balance - total_spent;
        refund_tx_build.replace_output(back_to_wallet_idx, &output_back_to_wallet);
        let refund_tx = refund_tx_build.sign();
        

        let result = wallet.send_tx(&refund_tx).await?;
        println!("Refund transaction sent with ID: {}", result);
        println!("You can now restart the process with the correct amount or token");

        return Ok(());  // This returns control back to the main menu
    }

    println!("Deposit ok... Let's publish the sell offer on Ergon chain");
    sleep(Duration::from_secs(2)).await;


    let token_id_vec = Vec::from(token_id);
    let (mut lock_tx_build, balance, _balance_token) = wallet.init_transaction(Some(temp_address.clone()), Some(temp_secret_key), Some(token_id_vec)).await?;   

    let output = EnforceOutputsOutput {
        value: 5,  // ignored for script hash generation
        enforced_outputs: vec![
            Box::new(SLPSendOutput {
                token_type: 1,
                token_id,
                output_quantities: vec![0, sell_amount],
            }),
            Box::new(P2PKHOutput {
                value: buy_amount,
                address: receiving_address.clone(),
            }),
        ],
        cancel_address: cancel_address.clone(),
        is_cancel: None,
    };
    let pkh = hash160(&output.script().to_vec());
    let addr_slp = Address::from_bytes_prefix(
        "ergon",
        AddressType::P2SH,
        pkh.clone(),
    );
    
    // Print the P2SH addresses
    println!("P2SH Address: {}", addr_slp.cash_addr());


    let mut token_id = [0; 32];
    token_id.copy_from_slice(&hex::decode(&received_token_id_str)?);
    
    let output_slp = SLPSendOutput {
        token_type: 1,
        token_id,
        output_quantities: match received_amount {
            Some(amount) => vec![amount, 0],
            None => return Err("Received amount is None".into()),
        },        
    };


    let send_output = P2SHOutput {
        output: output,
    };
    
    let back_output = P2PKHOutput {
        value: 5, // Value in satoshis
        address: temp_address.clone(),
    };


    let mut output_back_to_wallet = P2PKHOutput {
        value: 0,  // for generating tx size
        address: wallet.address().clone(),
    };



    lock_tx_build.add_output(&output_slp);
    lock_tx_build.add_output(&send_output);
    lock_tx_build.add_output(&back_output);


    let back_to_wallet_idx = lock_tx_build.add_output(&output_back_to_wallet);

    let fee = 10;
    let total_spent =
            back_output.value() +
            fee;
    //println!("Total about to be spent: {}", total_spent);

    output_back_to_wallet.value = balance - total_spent;
    lock_tx_build.replace_output(back_to_wallet_idx, &output_back_to_wallet);
    let lock_tx = lock_tx_build.sign();
    
    let lock_result = wallet.send_tx(&lock_tx).await?;
    println!("Locking transaction sent with ID: {}", lock_result);
    sleep(Duration::from_secs(2)).await;

    let (mut listing_tx_build, balance, _balance_token) = wallet.init_transaction(None, None, None).await?;
    //println!("Balance is: {}", balance);
    
    // Decode the hexadecimal string into a byte array
    let mut tx_hash_bytes = hex::decode(&lock_result)
        .map_err(|_| "Failed to decode hex string")?; // Handle the error appropriately
    
    // Reverse the byte order for endianness
    tx_hash_bytes.reverse();
    
    // Now `tx_hash_bytes` is a byte array (`Vec<u8>`) with correct endianness
    let tx_id = tx_hex_to_hash(&tx_hash_bytes);
    let tx_id_bytes = hex::decode(&tx_id).map_err(|_| "Failed to decode hex string")?;

    // Ensure the length is 32 and convert to array
    let tx_id_array = if tx_id_bytes.len() == 32 {
        let mut array = [0u8; 32];
        array.copy_from_slice(&tx_id_bytes);
        array
    } else {
        return Err("Invalid tx_id length".into());
    };

    
    let trade_offer_output = TradeOfferOutput {
        tx_id: tx_id_array,
        output_idx: 1,
        sell_amount,
        buy_amount,
        receiving_address: receiving_address.clone(),
        cancel_address: cancel_address.clone(),
    };
    

    //println!("TradeOfferOutput Details: tx_id: {:?}, output_idx: {}, sell_amount: {}, buy_amount: {}, receiving_address: {:?}, cancel_address: {:?}", 
        //trade_offer_output.tx_id, trade_offer_output.output_idx, trade_offer_output.sell_amount, trade_offer_output.buy_amount, trade_offer_output.receiving_address, trade_offer_output.cancel_address);
    

    listing_tx_build.add_output(&trade_offer_output.into_output());

    //println!("Added TradeOfferOutput to transaction build.");


    let mut send_output = P2PKHOutput {
        value: 0,
        address: wallet.address().clone(),
    };

    let signal_output = P2PKHOutput {
        value: 5,
        address: signal_address.clone(),
    };
    listing_tx_build.add_output(&signal_output);

    let fee = 10;
    let total_spent =
        signal_output.value() +
            fee;

    if total_spent > balance {
        println!("The broadcast transaction cannot be sent due to insufficient funds");
    }

    //println!("Total about to be spent: {}", total_spent);

    send_output.value = balance - total_spent;
    listing_tx_build.add_output(&send_output);


    let listing_tx = listing_tx_build.sign();
    let result = wallet.send_tx(&listing_tx).await?;
    println!("The trade listing transaction ID is: {}", result);


    Ok(())
}

pub async fn accept_trades_interactive(wallet: &Wallet,  token_symbol: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let (_tx_build, balance, _balance_token) = wallet.init_transaction(None, None, None).await?;
    if balance < 1000 {
        println!("Your balance ({}) is too low.", balance);
        println!("You need at least 1000 ergoshis to access trading.");
        println!("Please fund some XRG to your wallet's address: {}", wallet.address().cash_addr());                  
        return Ok(());
    }
    println!("Loading and confirming trades... (Note: this might take a few seconds)");

    let signal_address_str = "ergon:qph2jxmrk2uswgvfdjeld32hrxjpxz8nyyy248su37";
    let signal_address = Address::from_cash_addr(signal_address_str.to_string())
        .expect("Invalid address");
    let signal_address_utxos = wallet.get_utxos(&signal_address).await?;

    // Create a vector to store TradeOfferOutputs
    let mut trades: Vec<TradeOfferOutput> = Vec::new();
    for proto_utxo in &signal_address_utxos {
        if let Some(ref outpoint) = proto_utxo.outpoint {
            // Check if txid is of the correct length and convert to [u8; 32]
            let txid = if outpoint.txid.len() == 32 {
                let mut txid_array = [0u8; 32];
                txid_array.copy_from_slice(&outpoint.txid);
                Sha256d::new(txid_array)
            } else {
                return Err("Invalid txid length".into());
            };
    
            let signal_tx_details = wallet.get_transaction_details(&txid).await?;
            //println!("Signal TX : {:#?}", signal_tx_details); // Print the parsed trade offer
    
            if let Some(output0) = signal_tx_details.outputs.get(0) {
                let exch_script = &output0.output_script;
                //println!("Script {:?}", exch_script);
    
                // Parse the exchange script and handle potential errors
                match EXCH::parse_exch_script(exch_script.clone()) {
                    Ok(trade_offer) => {
                        // Add the valid trade_offer to the vector
                        trades.push(trade_offer);
                    }
                    Err(err) => {
                        // Handle the error (you can print it or log it)
                        println!("Error parsing trade offer: {}", err);
                    }
                }
            }
        }
    }

    let tx_hashes = trades.iter().map(|trade| {
        hex::encode(&trade.tx_id.iter().cloned().rev().collect::<Vec<_>>())
    }).collect::<Vec<_>>();

    let tx_hashes_chunks: Vec<Vec<String>> = tx_hashes.chunks(20)
        .map(|chunk| chunk.to_vec())
        .collect();
    
    // Collect the results from the async operations
    let valid_trades_results: Vec<ValidTrade> = stream::iter(tx_hashes_chunks)
        .then(|chunk| {
            async move {
                let futures = chunk.into_iter().map(|txid| {
                    let txid_hash = Sha256d::from_slice(
                        &hex::decode(&txid)
                            .expect("Failed to decode txid")
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                    ).unwrap();
                    //println!("Txid hash: {:?}", txid_hash);
    
                    async move {
                        match wallet.get_transaction_details(&txid_hash).await {
                            Ok(tx_details) => {
                                //println!("Transaction Details From Chronik: {:?}", tx_details);
    
                                // Check if any output contains an SLP token and is unspent
                                let has_unspent_slp_token = tx_details.outputs.iter().any(|output| {
                                    output.slp_token.is_some() && output.spent_by.is_none()
                                });
    
                                // Check if any input has slp_burn set to None
                                let all_inputs_have_no_slp_burn = tx_details.inputs.iter().all(|input| {
                                    input.slp_burn.is_none()
                                });
    
                                // Extract token_id from slp_meta
                                let token_id = if let Some(slp_meta) = tx_details.slp_tx_data.as_ref().and_then(|data| data.slp_meta.as_ref()) {
                                    hex::encode(&slp_meta.token_id)
                                } else {
                                    String::new() // or handle the case where slp_meta or token_id is not
                                };    
                                let amount = tx_details.outputs.iter()
                                .filter_map(|output| output.slp_token.as_ref().map(|slp_token| slp_token.amount))
                                .next()
                                .unwrap_or(0); // Default to 0 if no SLP token is found in outputs
    
                            // Create ValidTrade instance
                            ValidTrade {
                                txid: txid.clone(),
                                token_id,
                                token_value: amount,
                                valid: has_unspent_slp_token && all_inputs_have_no_slp_burn
                            }
                        },
                        Err(e) => {
                            eprintln!("Error getting transaction details: {}", e);
    
                            // Handle error, possibly by creating a ValidTrade with valid set to false
                            ValidTrade {
                                txid: txid.clone(),
                                token_id: String::new(), // or handle the error differently
                                token_value: 0,
                                valid: false
                            }
                        }
                    }
                }
            });
    
                let results = futures::future::join_all(futures).await;
                //println!("Results: {:?}", results);
                results
            }
        })
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .flatten()
        .collect();

    // Map ValidTrade instances to their respective txid for easy lookup
    let valid_trades_map: HashMap<String, ValidTrade> = valid_trades_results
        .into_iter()
        .filter(|trade| trade.valid)
        .map(|trade| (trade.txid.clone(), trade))
        .collect();

    // Associate each TradeOfferOutput with its corresponding ValidTrade
    let detailed_trades: Vec<(TradeOfferOutput, Option<ValidTrade>)> = trades
        .into_iter()
        .map(|trade_offer| {
            let txid_hex = hex::encode(&trade_offer.tx_id.iter().cloned().rev().collect::<Vec<_>>());
            let valid_trade = valid_trades_map.get(&txid_hex);
            (trade_offer, valid_trade.cloned())
        })
        .filter(|(_, valid_trade)| valid_trade.is_some()) // Keep only trades with corresponding valid entries
        .collect();

    // Fetch token details and associate them with the trades
    let unique_token_ids: HashSet<String> = detailed_trades
        .iter()
        .filter_map(|(_, valid_trade)| valid_trade.as_ref().map(|trade| trade.token_id.clone()))
        .collect();
    let mut token_details_map: HashMap<String, TokenEntry> = HashMap::new();
    for token_id in unique_token_ids {
        let token_ids_slice = &[&token_id as &str];
        if let Ok(token_details_list) = fetch_tokens(token_ids_slice).await {
            if let Some(token_details) = token_details_list.first() {
                token_details_map.insert(token_id, token_details.clone());
            }
        } else {
            eprintln!("Error fetching details for token ID {}", token_id);
        }
    }

    // Step 3: Associate token details with trades and optionally filter by symbol
    let mut final_trades: Vec<(TradeOfferOutput, Option<ValidTrade>, Option<TokenEntry>)> = Vec::new();
    for (trade_offer, valid_trade) in detailed_trades {
        let token_details = valid_trade.as_ref().and_then(|trade| token_details_map.get(&trade.token_id));
        final_trades.push((trade_offer, valid_trade, token_details.cloned()));
    }

    if let Some(symbol) = token_symbol {
        final_trades.retain(|(_, _, token_details)| {
            token_details.as_ref().map_or(false, |details| {
                details.symbol.as_ref() == Some(&symbol)
            })
        });
    }
    

    // Corrected sorting logic
    final_trades.sort_by(|(trade_offer1, _, token_details1), (trade_offer2, _, token_details2)| {
        let factor1 = token_details1.as_ref().map(|td| 10.0f64.powi(-(td.decimals as i32))).unwrap_or(1.0);
        let sell_amount_display1 = trade_offer1.sell_amount as f64 * factor1;
        let price1 = trade_offer1.buy_amount as f64 / sell_amount_display1;
    
        let factor2 = token_details2.as_ref().map(|td| 10.0f64.powi(-(td.decimals as i32))).unwrap_or(1.0);
        let sell_amount_display2 = trade_offer2.sell_amount as f64 * factor2;
        let price2 = trade_offer2.buy_amount as f64 / sell_amount_display2;
    
        price1.partial_cmp(&price2).unwrap_or(Ordering::Equal)
    });
    

    // Now the valid_trades vector is sorted by price

    let (mut tx_build, balance, _balance_token) = wallet.init_transaction(None, None, None).await?;
    println!("Your balance: {} ergoshis", balance);
    println!("Current trade offers:");
    println!("{:^3} | {:^15} | {:^14} | {:^10} | {:^32} |", 
             "#".bright_yellow(), 
             "Selling".bright_cyan(), 
             "Asking".bright_green(), 
             "Price per token".bright_magenta(), 
             "Token ID".bright_blue());
    println!("{}", "---------------------------------------------------------------------------------------------".bright_white());
    for (idx, (trade_offer, _, token_details)) in final_trades.iter().enumerate() {
        let token_factor = token_details.as_ref().map(|td| 10.0f64.powi(td.decimals as i32)).unwrap_or(1.0);
        let sell_amount_display = trade_offer.sell_amount as f64 / token_factor;
        let price = trade_offer.buy_amount as f64 / sell_amount_display;
        
        let unknown_symbol = String::from("<unknown>");
        let symbol = token_details.as_ref().and_then(|td| td.symbol.as_ref()).unwrap_or(&unknown_symbol);
        let token_id_display = token_details
            .as_ref()
            .map(|td| &td.id[..std::cmp::min(32, td.id.len())]) // Safely slice the string
            .unwrap_or("<unknown>");

        println!("{:3} | {:<15} | {:<14} | {:<15} | {:8} |",
                 idx.to_string().bright_yellow(),
                 format!("{} {}", sell_amount_display, symbol).bright_cyan(),
                 format!("{:.8} ergoshi", trade_offer.buy_amount).bright_green(),
                 format!("{:.4} ergoshi", price).bright_magenta(),
                 token_id_display.bright_blue());
                }
    
    
    
    if final_trades.len() == 0 {
        println!("There currently aren't any open trades on the entire network.");
        return Ok(());
    }
    if balance < wallet.dust_amount() {
        println!("Your balance ({}) isn't sufficient to broadcast a transaction. Please fund some \
                  XRG to your wallet's address: {}", balance, wallet.address().cash_addr());
        return Ok(());
    }

    print!("{}", format!("Enter the trade offer number to accept (0-{}): ", final_trades.len() - 1).bright_yellow());
    io::stdout().flush()?;
    let offer_idx_str: String = read!("{}\n");
    let offer_idx_str = offer_idx_str.trim();
    if offer_idx_str.is_empty() {
        println!("{}", "Bye!".bright_green());
        return Ok(());
    }
    let offer_idx: usize = offer_idx_str.parse().map_err(|err| {
        println!("{}", format!("Invalid number: {}", err).red());
        println!("{}", "Exit.".red());
        err
    })?;

    let (trade_offer, valid_trade, token_details) = match final_trades.get(offer_idx) {
        Some(trade_info) => trade_info,
        None => {
            println!("Invalid number");
            println!("Exit.");
            return Ok(());
            },
        };
    let trade: &TradeOfferOutput = trade_offer;
    let trade_token_details: &TokenEntry = match token_details {
        Some(details) => details,
            None => {
            println!("Token details not found for the selected trade.");
            return Ok(());
            }
        };
    println!("{}", "You selected the following trade:".bright_white());
    println!("{:20}{:10} {:<}", 
            "Purchase amount:".bright_white(), 
            format!("{}", trade.sell_amount as f64 * 10.0f64.powi(-(trade_token_details.decimals as i32))).bright_green(), 
            option_str(&trade_token_details.symbol).bright_magenta());
    println!("{:20}{:10} ergoshi", "Spend amount:".bright_white(), trade.buy_amount.to_string().bright_green());
    println!("{:20}{}", "Token ID:".bright_white(), trade_token_details.id);
    println!("{:20}{}", "Token symbol:".bright_white(), option_str(&trade_token_details.symbol));
    println!("{:20}{}", "Token name:".bright_white(), option_str(&trade_token_details.name));
    println!("{:20}{}", "Token timestamp:".bright_white(), trade_token_details.timestamp);
    println!("{:20}{}", "Token document URI:".bright_white(), option_str(&trade_token_details.document_uri));
    println!("{}", "--------------------------------------------------".bright_blue());
    if balance < trade.buy_amount {
        println!(
            "{}",
            format!(
                "Insufficient funds. The trade asks for {} ergoshis but your wallet's balance is only {} ergoshis",
                trade.buy_amount, balance
            ).red().bold()
        );
        println!("{}", "Note that you also need to pay for the transaction fees, which are ~20 ergoshis".bright_red());
    }
    

    let addr = loop {
        print!("{}", "Enter the ergon address to send the tokens to: ".bright_yellow());
        io::stdout().flush()?;
        let receiving_addr_str: String = read!("{}\n");
        let receiving_addr_str = receiving_addr_str.trim();
        if receiving_addr_str.len() == 0 {
            println!("Bye!");
            return Ok(());
        }
        let addr = match Address::from_cash_addr(receiving_addr_str.to_string()) {
            Ok(addr) => addr,
            Err(err) => {
                println!("Please enter a valid address: {:?}", err);
                continue;
            }
        };
        if addr.prefix() != "ergon" {
            println!("{}", "Please enter an ergon address, it starts with 'ergon'.".red());
            continue;
        }
        break addr;
    };

    let mut token_id = [0; 32];
    token_id.copy_from_slice(&hex::decode(&trade_token_details.id)?);
    let output_slp = SLPSendOutput {
        token_type: 1,
        token_id,
        output_quantities: vec![0, trade.sell_amount],
    };
    //println!("SLP output: {:?}", output_slp.token_id);
    let output_buy_amount = P2PKHOutput {
        value: trade.buy_amount,
        address: trade.receiving_address.clone(),
    };

    let input_output = EnforceOutputsOutput {
        value: 5,
        enforced_outputs: vec![
            Box::new(output_slp.clone()),
            Box::new(output_buy_amount.clone()),
        ],
        cancel_address: trade.cancel_address.clone(),
        is_cancel: Some(false),
    };

    let output_sell_amount = P2PKHOutput {
        value: wallet.dust_amount(),
        address: addr,
    };
    let mut output_back_to_wallet = P2PKHOutput {
        value: 0,  // for generating tx size
        address: wallet.address().clone(),
    };

    // Extract txid from valid_trade
    let txid = match valid_trade {
        Some(vt) => &vt.txid,
        None => {
            println!("Valid trade details not found for the selected trade.");
            return Ok(());
        }
    };

    let tx_hash_bytes = hex::decode(&txid)
        .map_err(|_| "Failed to decode hex string")?; // Handle error appropriately
    let mut tx_id = [0u8; 32]; // Create an empty [u8; 32] array
    tx_id.copy_from_slice(&tx_hash_bytes); // Copy the reversed bytes into tx_id


    tx_build.add_utxo(Utxo {
        outpoint: TxOutpoint {
            tx_hash: tx_id,
            output_idx: trade.output_idx,
        },
        sequence: 0xffff_ffff,
        output: Box::new(
            P2SHOutput { output: input_output },
        ),
        // arbitrary, totally randomly generated, key
        key: secp256k1::SecretKey::from_slice(b"TruthIsTreasonInTheEmpireOfLies.")?,
    });
    //println!("P2SH: {:?}", tx_id);
    tx_build.add_output(&output_slp);
    tx_build.add_output(&output_buy_amount);
    tx_build.add_output(&output_sell_amount);
    let back_to_wallet_idx = tx_build.add_output(&output_back_to_wallet);

    let fee = 20;
    let total_spent =
        output_slp.value() +
            output_buy_amount.value() +
            output_sell_amount.value() +
            fee;
    if total_spent > balance {
        println!("Including fees and dust outputs, this transaction will spend {} sats, but \
                  your wallet's balance is only {} sats", total_spent, balance);
        return Ok(());
    }
    output_back_to_wallet.value = balance - total_spent;
    tx_build.replace_output(back_to_wallet_idx, &output_back_to_wallet);
    let tx = tx_build.sign();

    let mut tx_ser = Vec::new();
    tx.write_to_stream(&mut tx_ser)?;

    println!("{}", "Type \"hex\" (without quotes) to show the transaction hex instead of broadcasting.".bright_yellow());
    println!("After broadcasting, your balance will be {} ergoshis.", (balance - total_spent).to_string().green());
    print!("{}", "Should the transaction be broadcast now to seal the deal? Type \"yes\" (without quotes): ".bright_cyan());
    io::stdout().flush()?;
    let confirm_send: String = read!("{}\n");
    match confirm_send.to_ascii_lowercase().trim() {
        "yes" => {
            let response = wallet.send_tx(&tx).await?;
            println!("{} {}", "Sent transaction. Transaction ID is:".bright_green(), response.to_string().yellow());
        },
        "hex" => {
            println!("{}", hex::encode(&tx_ser).bright_white());
        },
        _ => {},
    }
    
    Ok(())
}