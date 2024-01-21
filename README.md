# Ergonex - An On-Chain Trading Terminal for Ergon

![image](https://github.com/ErgonSurfer/ergon-slpagora/assets/153525861/0a5269d8-ea98-4143-936f-eb86362bcaeb)


**Disclaimer: This is an experimental tool and is intended for educational purposes only. Use at your own risk. Loss of funds can occur due to bugs or misuse. The developers do not take any responsibility for financial losses.**

## Introduction

Ergonex is a powerful and user-friendly on-chain trading terminal for the Ergon blockchain. It is an evolution of the popular SLPAgora tool, offering enhanced features and a more intuitive interface for trading Ergon-based assets.

Ergonex leverages the capabilities of the Ergon blockchain and is powered by the SLP (Simple Ledger Protocol) token protocol. It allows users to trade SLP tokens directly on the Ergon blockchain, providing a seamless and secure trading experience.

## Key Features

- **Covenant-Based Trading:** Ergonex enables trustless trading using Ergon covenants, ensuring that transactions are secure and tamper-proof.
- **User-Friendly Interface:** The intuitive user interface makes trading easy for both beginners and experienced users.
- **Integration with Chronik Indexer:** Ergonex is powered by the amazing Chronik Indexer, providing real-time access to Ergon blockchain data.
- **Multi-Platform Support:** Ergonex is available as a cross-platform tool, with binaries for Linux and macOS.

## Installation 

### Using the Provided Binaries:

If you prefer to use the pre-built binaries for Linux and macOS, follow these steps:

#### Linux

1. Download the Linux binary from the repo.

2. Make the binary executable:

   ```bash
    chmod +x ergonex-linux

3. Run Ergonex:

   ```bash
    ./ergonex-linux

#### macOS

1. Download the macOS DMG from the repo.

2. Open the DMG file.

3. Drag the Ergonex application into the Applications folder.

4. Right-click on Ergonex and choose "Open." (Note: The DMG is not notarized, so you may need to bypass macOS security settings.)

5. Run Ergonex from the Applications folder.

### Building from source

Before running Ergonex, you'll need Rust and Cargo installed on your system. Follow these steps to install them:

#### Linux:

1. Open a terminal window.

2. Run the following command to install Rust and Cargo:

   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

3. Follow the on-screen instructions to complete the installation.

#### macOS:


1. Open a terminal window.

2. Install Homebrew (if not already installed):

   ```bash
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"

3. Install Rust and Cargo using Homebrew:

   ```bash
    brew install rust


#### Building and Running Ergonex

After installing Rust and Cargo, you can build and run Ergonex using the following steps:

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/ErgonSurfer/ergonex.git
   cd ergonex

2. Build Ergonex:

   ```bash
    cargo build --release

3. Run Ergonex:

   ```bash
    cargo run --release
    



## Getting Started

Once Ergonex is up and running, you can start trading SLP tokens on the Ergon blockchain. The user-friendly interface and real-time data provided by Chronik Indexer make it easy to navigate and execute trades.

## Contributions and Issues

Contributions to Ergonex are welcome! If you encounter any issues or have suggestions for improvements, please open an issue on GitHub.

## License

Ergonex is open-source software licensed under the MIT License.
