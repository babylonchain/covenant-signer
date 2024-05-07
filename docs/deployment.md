# Covenant Signer Setup Deployment

This document covers the deployment of a secure Covenant Signer setup,
following the proposed [Architecture](../README.md#Architecture).

## 1. Overview

As per the proposed Architecture, we'll be deploying the following components:
- **Covenant Signer**: A publicly reachable server which receives partially
  signed unbonding transactions and returns the same transactions signed by a
  Covenant key
- **bitcoind Offline Wallet**: A server containing a single wallet that hosts a
  single Covenant BTC key; the server is used to sign unbonding transactions
  forwarded by the Covenant Signer
- **bitcoind Full Node**: A Bitcoin full node used to verify whether the
  to-be-unbonded staking transaction has already been submitted to Bitcoin and
  had the required amount of BTC confirmations

**For a production system, we strongly recommend that the bitcoind Offline Wallet
and Full Node are distinct bitcoind instances operating on different hosts**.
For a PoC setup, one bitcoind instance can serve as both the entities, or both
bitcoind instances can run on the same host.

## 2. bitcoind setup (applies to both Offline Wallet and Full Node)

The Installation, Configuration and Boot steps for the bitcoind Offline Wallet
and Full Node are almost identical.

### A. Installation

Download and install the bitcoin binaries according to your operating system
from the official
[Bitcoind Core registry](https://bitcoincore.org/bin/bitcoin-core-26.0/). We
propose using version `26.0`.

### B. Configuration

bitcoind is configured through a main configuration file named `bitcoin.conf`.

Depending on the operating system, the configuration file should be placed under
the corresponding path:
- **MacOS**: `/Users/<username>/Library/Application Support/Bitcoin`
- **Linux**: `/home/<username>/.bitcoin`
- **Windows**: `C:\Users\<username>\AppData\Roaming\Bitcoin`

Both servers can utilize the following base parameter skeleton (adapted for BTC
signet network):

```shell
# Accept command line and JSON-RPC commands
server=1
# Enable creation of legacy wallets
deprecatedrpc=create_bdb
# RPC server settings
rpcuser=<rpc-username>
rpcpassword=<rpc-password>
# Optional: In case of non-mainnet BTC node, also specify the network that your
# node will operate; for this example, utilizing signet
signet=1
[signet]
rpcport=38332
rpcbind=0.0.0.0
# Optional: Needed for remote node connectivity
rpcallowip=0.0.0.0/0
```

It's very important to ensure that **the Offline Wallet server does not
connect with other nodes**. To achieve this, append the following to the end
of the Offline Wallet server's configuration:

```shell
# IMPORTANT: Offline Wallet server shouldn't connect to any external node
connect=0
```

Note: In case both your bitcoind Offline Wallet and Full Node servers run on the
same node (**not recommended, please check the
[infrastructure guidelines](#appendix-infrastructure-specific-guidelines)**),
you'll need to use different, non-default directories for each server.

### C. Boot

In case you're using the default bitcoind home directory, you can boot your
bitcoind server by simply running:

```shell
bitcoind
```

In case you're using a non-default home directory:

```shell
bitcoind -datadir=/path/to/bitcoin/home
```

#### Linux-only: Systemd service definition

For Linux systems, you can persist each bitcoind server startup process through
the following process.

1. Create a systemd service definition
    ```shell
    # Create the service file
    sudo tee /etc/systemd/system/bitcoind.service >/dev/null <<EOF
    [Unit]
    Description=bitcoin signet node
    After=network.target

    [Service]
    User=<user>
    Type=simple
    ExecStart=/path/to/bitcoind \
        -datadir=/path/to/bitcoin/home
    Restart=on-failure
    LimitNOFILE=65535

    [Install]
    WantedBy=multi-user.target
    EOF
    ```

2. Start the service
    ```shell
    sudo systemctl daemon-reload
    sudo systemctl enable bitcoind
    sudo systemctl start bitcoind
    ```

## 3. bitcoind Offline Wallet: Create **legacy** wallet and Covenant Key

The bitcoind Offline Wallet server will host a **legacy** (non-descriptor) BTC
wallet. This wallet will contain a single address, whose private key will
be used as the Covenant BTC key to sing PSBTs.

**Throughout this whole process, the bitcoind Offline Wallet should not have
internet access.**

1. Create the wallet
    ```shell
    bitcoin-cli -named createwallet \
        wallet_name=<wallet_name> \
        passphrase="<passphrase>" \
        load_on_startup=true \
        descriptors=false
    ```

    Flags explanation:
    - `wallet_name`: The name of the wallet
    - `passphrase`: The passphrase that will be used to encrypt the wallet
      (**IMPORTANT, MUST BE SAFELY STORED**)
    - `load_on_startup=true`: Ensures that the wallet is automatically loaded in
      case of server restart
    - `descriptors=false`: Creates a legacy wallet

2. Create a new address
    ```shell
    # Save the output of this command
    bitcoin-cli getnewaddress
    ```

3. Obtain 33-byte BTC public key derived from the above address
    ```shell
    bitcoin-cli getaddressinfo <btc_address> | jq -r .pubkey
    ```

Note: In case you used a non-default bitcoin home directory, also include the
`-datadir=/path/to/bitcoin/home` flag in all the above `bitcoin-cli` commands.

## 4. Covenant Signer setup

### A. Installation

#### Prerequisites

This project requires Go version 1.21 or later.

Install Go by following the instructions on the official Go installation guide.
Downloading the code

#### Download the code

To get started, clone the repository to your local machine from Github; you can
choose a specific version from the official
[releases](https://github.com/babylonchain/covenant-signer/releases) page.

```shell
git clone https://github.com/babylonchain/covenant-signer.git
cd covenant-signer
git checkout <release-tag>
```

#### Build and install the binary

At the top-level directory of the project

```shell
make install
```

The above command will build and install the `covenant-signer` binary to
`$GOPATH/bin`, which is the daemon program for the Covenant Signer server.

If your shell cannot find the installed binaries, make sure `$GOPATH/bin` is in
the `$PATH` of your shell. The following updates to `$PATH` can be performed to
this direction:

```shell
export PATH=$HOME/go/bin:$PATH
echo 'export PATH=$HOME/go/bin:$PATH' >> ~/.profile
```

### B. Configuration

The default configuration file (`config.toml`) should be dumped using the
following command:

```shell
covenant-signer dump-cfg
```

Depending on the operating system, the configuration file will be placed under
the corresponding path:
- **MacOS**: `/Users/<username>/Library/Application Support/Signer`
- **Linux**: `/home/<username>/.signer`
- **Windows**: `C:\Users\<username>\AppData\Local\Signer`

Some important configuration file parameters are listed below:

```shell
#### Parameters related to the bitcoind full node
[btc-config]
# Btc node host
host = <bitcoind_full_node_endpoint>
# Btc node user
user = <bitcoind_full_node_username>
# Btc node password
pass = <bitcoind_full_node_password>
# Btc network (testnet3|mainnet|regtest|simnet|signet)
network = <btc_network>

#### Parameters related to the bitcoind wallet
[btc-signer-config]
# Btc node host
host = <bitcoind_wallet_endpoint>
# Btc node user
user = <bitcoind_wallet_username>
# Btc node password
pass = <bitcoind_wallet_password>
# Btc network (testnet3|mainnet|regtest|simnet|signet)
network = <btc_network>

[server-config]
# The address to listen on
host = "127.0.0.1"
# The port to listen on
port = 9791
```

The Covenant Signer also consumes an additional configuration file containing
global parameters (`global-params.json`), ie parameters which are shared between
several services of the Babylon BTC Staking system. The file resides under the
same path as `config.toml`.

The file contents can be obtained from
[here](https://github.com/babylonchain/phase1-devnet/tree/main/parameters).

### C. Boot

To start the Covenant Signer, execute the following:

```shell
covenant-signer start --config /path/to/signer/home/config.toml
```

## Appendix: Infrastructure-specific guidelines

Deploying the Covenant Signer setup in a secure manner is of the highest
importance due to its pivotal role in the unbonding process.

We strongly encourage you to follow the following set of guidelines.

### Resource requirements

The underlying storage to meet these requirements should be encrypted.

#### Covenant Signer

- An instance with at least 4G RAM and 2 vCPUs is expected
- The component can be horizontally scaled with traffic being load-balanced
  behind a reverse proxy

#### bitcoind Offline Wallet

- An instance with at least 4G RAM and 2 vCPUs is expected
- At least 10G of persistent storage should available for the BTC Wallet

#### bitcoind Full Node

- An instance with at least 4G RAM and 2 vCPUs is expected
- Depending on the BTC network, enough storage to host the complete Bitcoin
  ledger should be attached (800G for the Mainnet, 100G for the Testnet3,
  50G for the Signet)

### Networking

#### Covenant Signer

- The Covenant Signer is publicly reachable on the configured server port
- The port accepts only TLS traffic (can be achieved by exposing the Covenant
  Signer through a reverse proxy)
- Ideally, the Covenant Signer is also protected against DDoS attacks

#### bitcoind Offline Wallet

- The bitcoind Offline Wallet is only reachable from the Covenant Signer at
  the designated BTC RPC port
- The bitcoind Offline Wallet accepts only TLS traffic
- The bitcoind Offline Wallet lives on a private network and doesn't have
  internet access

#### bitcoind Full Node

Same with the bitcoind Offline Wallet, but the Node should have internet access
to sync the BTC ledger.

### Backups

Both the bitcoind Offline Wallet and Full Node servers should be frequently
backed up on a filesystem level to ensure continuous operation in case of
failure / data corruption.

We suggest a rolling backup method comprising hourly, daily and weekly backups.

#### Backing up and restoring the bitcoind wallet

For the bitcoind wallet, bitcoin-level backups can also be obtained through the
following process:

```shell
# Backup the wallet
bitcoin-cli -rpcwallet=<wallet-name> backupwallet /path/to/backup/wallet.dat
# Restore the wallet
bitcoin-cli restorewallet <wallet-name> /path/to/backup/wallet.dat
```

### Monitoring

As the Covenant Signer will be exposing Prometheus metrics, this section will be
focused around Prometheus-based monitoring.

#### Covenant Signer

Healthchecks should be configured on the `/v1/sign-unbonding-tx` server HTTP
endpoint.

One approach to perform HTTP/S healthchecks and expose results in the form of
Prometheus metrics is the
[Prometheus Blackbox Exporter](https://github.com/prometheus/blackbox_exporter).

These metrics can then be scraped by a Prometheus instance.

#### bitcoind

The bitcoind server availability can be polled through Prometheus Blackbox
Exporter.

Bitcoin-specific Prometheus metrics can also be exposed by utilizing any
open-source Prometheus bitcoind exporter
([example](https://github.com/jvstein/bitcoin-prometheus-exporter?tab=readme-ov-file)).
