pub mod message_header;
pub mod message;
pub mod message_error;
pub mod version_message;
pub mod hash;
pub mod serialize;
pub mod tx;
pub mod incomplete_tx;
pub mod script;
pub mod script_interpreter;
pub mod address;
pub mod outputs;
pub mod wallet;
pub mod trade;
pub mod exch;
pub mod display_qr;

use std::io::{self, Write, Read};
use text_io::{read};
use std::env;
use colored::*;
use crate::wallet::Wallet;



const WALLET_FILE_NAME: &str = "trade.dat";
const SLP_AGORA_PATH: &str = ".slpagora";


fn ensure_wallet_interactive() -> Result<wallet::Wallet, Box<dyn std::error::Error>> {
    let trades_dir = dirs::home_dir().unwrap_or(env::current_dir()?).join(SLP_AGORA_PATH);
    let wallet_file_path = trades_dir.as_path().join(WALLET_FILE_NAME);
    std::fs::create_dir_all(trades_dir)?;
    match std::fs::File::open(&wallet_file_path) {
        Ok(mut file) => {
            println!("Using wallet file at {}", wallet_file_path.display());
            let mut secret_bytes = [0; 32];
            file.read(&mut secret_bytes)?;
            Ok(wallet::Wallet::from_secret(&secret_bytes)?)
        },
        Err(ref err) if err.kind() == io::ErrorKind::NotFound => {
            println!("Creating wallet at {}", wallet_file_path.display());
            use rand::RngCore;
            let mut rng = rand::rngs::OsRng::new().unwrap();
            let mut secret_bytes = [0; 32];
            rng.fill_bytes(&mut secret_bytes);
            let _ = secp256k1::SecretKey::from_slice(&secret_bytes)?;
            std::fs::File::create(wallet_file_path)?.write(&secret_bytes)?;
            Ok(wallet::Wallet::from_secret(&secret_bytes)?)
        },
        err => {err?; unreachable!()},
    }
}

async fn show_balance(w: &Wallet) -> Result<(), Box<dyn std::error::Error>> {
    // Call the modified get_balance function
    w.get_balance().await?;

    // Display wallet address
    println!("Your wallet's address is: {}", w.address().cash_addr());
    // Assuming display_qr function is available and working
    display_qr::display(w.address().cash_addr().as_bytes());

    Ok(())
}



async fn do_transaction(w: &wallet::Wallet) -> Result<(), Box<dyn std::error::Error>> {
    let (mut tx_build, balance, _balance_token) = w.init_transaction(None, None, None).await?;
    println!("Your wallet's balance is: {} ergoshis or {} XRG.",
             balance,
             balance as f64 / 100_000_000.0);
    if balance < w.dust_amount() {
        println!("Your balance ({}) isn't sufficient to broadcast a transaction. Please fund some \
                  XRG to your wallet's address: {}", balance, w.address().cash_addr());
        return Ok(());
    }
    print!("Enter the address to send to: ");
    io::stdout().flush()?;
    let addr_str: String = read!("{}\n");
    let addr_str = addr_str.trim();
    let receiving_addr = match address::Address::from_cash_addr(addr_str.to_string())  {
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
        address: w.address().clone(),
    };
    let back_to_wallet_idx = tx_build.add_output(&output_back_to_wallet);
    let send_back_to_wallet_amount = if balance < send_amount + 10 {
        output_send.value = balance - 10;
        tx_build.replace_output(send_idx, &output_send);
        0
    } else {
        balance - (send_amount + 10)
    };
    if send_back_to_wallet_amount < w.dust_amount() {
        tx_build.remove_output(back_to_wallet_idx);
    } else {
        output_back_to_wallet.value = send_back_to_wallet_amount;
        tx_build.replace_output(back_to_wallet_idx, &output_back_to_wallet);
    }
    let tx = tx_build.sign();
    let response = w.send_tx(&tx).await?; // Use await here
    println!("Sent transaction. Transaction ID is: {}", response);

    Ok(())
}

#[tokio::main] // Make sure to use the async runtime

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ensure_wallet_interactive()?;

    // ERGON ASCII Art
    println!("{}", "
    ███████╗██████╗ ███████╗ ██████╗ ███╗   ██╗ ███████╗██╗  ██╗
    ██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║ ██╔════╝╚██╗██╔╝
    █████╗  ██████╔╝██ ████╗██║   ██║██╔██╗ ██║ █████╗   ╚███╔╝   
    ██╔══╝  ██╔══██╗██   ██║██║   ██║██║╚██╗██║ ██╔══╝   ██╔██╗ 
    ███████╗██║  ██║███████║╚██████╔╝██║ ╚████║ ███████╗██╔╝ ██╗
    ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝ ╚══════╝╚═╝  ╚═╝
    ".bright_yellow().bold());
    
    println!("{}", "Your wallet address is:".bright_yellow().underline());
    println!("{}", wallet.address().cash_addr().white());

    loop {
        println!("{}", "---------------------------------".blue().bold());
        println!("{}", "Select an option from below:".bright_green().bold());
        println!("{}", "1: Show wallet balance / fund wallet".bright_cyan());
//        println!("{}", "2: Send XRG from this wallet to an address".bright_cyan());
        println!("{}", "2: Send XRG/tokens from this wallet to an address".bright_cyan());
        println!("{}", "3: Create a new trade for a token on the Ergon blockchain".bright_cyan());
        println!("{}", "4: List all available token trades on the Ergon blockchain".bright_cyan());
        println!("{}", "5: List trades for a specific token symbol".bright_cyan());
        println!("{}", "Anything else: Exit".bright_red());
        print!("{}", "Your choice: ".bright_green());
        io::stdout().flush()?;
        let choice: String = read!("{}\n");
        match choice.trim() {
            "1" => show_balance(&wallet).await?,
            //"2" => do_transaction(&wallet).await?,
            "2" => wallet.get_balance_and_select_asset().await?,
            "3" => trade::create_trade_interactive(&wallet).await?,
            "4" => trade::accept_trades_interactive(&wallet, None).await?,
            "5" => {
                println!("{}", "Enter the token symbol to filter trades: ".bright_magenta());
                let token_symbol: String = read!("{}\n");
                trade::accept_trades_interactive(&wallet, Some(token_symbol)).await?;
            },
            _ => {
                println!("{}", "Bye, have a great time!".bright_green());
                return Ok(());
            },
        }
    }
}
