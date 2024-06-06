# Covenant Signer Setup Deployment

This document covers the deployment of a secure Covenant Signer setup,
following the proposed [Architecture](../README.md#Architecture).

## 1. Overview

The architecture contains the following components that need to be deployed:
- **Covenant Signer**: A publicly reachable server which receives
  unbonding transactions and returns the same transactions signed by
  the covenant emulator's key
- **bitcoind Offline Wallet**: A server containing a single wallet that hosts a
  single Covenant emulator BTC key; the server is used for signing unbonding transactions
  forwarded by the Covenant Signer
- **bitcoind Full Node**: A Bitcoin full node used to verify whether the
  to-be-unbonded staking transaction has already been submitted to Bitcoin and
  has the required amount of BTC confirmations

**For a production system, we strongly recommend that the bitcoind Offline Wallet
and Full Node are distinct bitcoind instances operating on different hosts**.
For a PoC/testnet setup, one bitcoind instance can serve as both the entities, or both
bitcoind instances can run on the same host.

## 2. bitcoind setup

The installation, configuration, and boot steps for the bitcoind Offline Wallet
and Full Node are almost identical. We combine them here for brevity.
In the next section, we will provide more details on how to perform certain
operations on the bitcoind Offline Wallet.

### 2.1. Hardware Requirements

Offline Wallet:
- An instance with at least 4G RAM and 2 vCPUs is expected
- At least 10G of persistent storage should be available for the BTC Wallet

Full Node:
- An instance with at least 4G RAM and 2 vCPUs is expected
- Depending on the BTC network, enough storage to host the complete Bitcoin
  ledger should be attached (800G for the Mainnet, 100G for the Testnet3,
  50G for the Signet)

*Notes on storage*
- The underlying storage for the offline wallet should be encrypted.
- Both the bitcoind Offline Wallet and Full Node servers should be frequently
  backed up on a filesystem level to ensure continuous operation in case of
  failure / data corruption.
  - We suggest a rolling backup method comprising hourly, daily and weekly backups.

### 2.2. Network Requirements

#### Offline Wallet

- The bitcoind Offline Wallet is only reachable from the Covenant Signer at
  the designated BTC RPC port
- The bitcoind Offline Wallet accepts only TLS traffic
- The bitcoind Offline Wallet lives on a private network and doesn't have
  internet access

#### Full Node

Same with the bitcoind Offline Wallet, but the Node should have internet access
to sync the BTC ledger.

### 2.3. Installation

Download and install the bitcoin binaries according to your operating system
from the official
[Bitcoind Core registry](https://bitcoincore.org/bin/bitcoin-core-26.0/).
All programs in this guide are compatible with version `26.0`.

### 2.4. Configuration

bitcoind is configured through a main configuration file named `bitcoin.conf`.

Depending on the operating system, the configuration file should be placed under
the corresponding path:
- **MacOS**: `/Users/<username>/Library/Application Support/Bitcoin`
- **Linux**: `/home/<username>/.bitcoin`
- **Windows**: `C:\Users\<username>\AppData\Roaming\Bitcoin`

Both servers can utilize the following base parameter skeleton (adapted for the BTC
signet network):

```shell
# Accept command line and JSON-RPC commands
server=1
# Enable transaction indexing
txindex=1
# RPC server settings
rpcuser=<rpc-username>
rpcpassword=<rpc-password>
# Optional: In case of non-mainnet BTC node,
# the following two lines specify the network that your
# node will operate; for this example, utilizing signet
signet=1
[signet]
# Port your bitcoin node will listen for incoming requests;
# below port is the canonical port for signet,
# for mainnet, typically 8332 is used
rpcport=38332
# Address your bitcoin node will listen for incoming requests
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

Notes:
- In case both your bitcoind Offline Wallet and Full Node servers run on the
  same node (**not recommended, please check the
  [infrastructure guidelines](#appendix-infrastructure-specific-guidelines)**),
  you'll need to use different, non-default directories for each server.
- Instead of hardcoding the RPC server password (`rpcpassword`) in the config,
  it is recommended to generate its salted hash and use the `rpcauth` field
  instead. To generate the salted hash, you can use
  [this platform](https://jlopp.github.io/bitcoin-core-rpc-auth-generator/)
  as reference - however, the salting operation should be executed locally.
  The resulting config value will look like this:
  ```shell
  rpcauth=<rpc-password-salted-hash>
  ```
- In case you will be connecting to BTC Mainnet network, ensure to remove the
  following config skeleton lines:
  ```shell
  signet=1
  [signet]
  ```

### 2.5. Boot

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

### 2.6. Monitoring

The bitcoind server availability can be polled through Prometheus Blackbox
Exporter.

Bitcoin-specific Prometheus metrics can also be exposed by utilizing any
open-source Prometheus bitcoind exporter
([example](https://github.com/jvstein/bitcoin-prometheus-exporter?tab=readme-ov-file)).

## 3. bitcoind Offline Wallet Operations

The following operations should be performed by the bitcoind offline wallet so
that it can be used by the covenant signer.

### 3.1. Create Descriptor Wallet and Covenant Key

The bitcoind Offline Wallet server will host a descriptor BTC
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
    ```

    Flags explanation:
    - `wallet_name`: The name of the wallet
    - `passphrase`: The passphrase that will be used to encrypt the wallet
      (**IMPORTANT, MUST BE SAFELY STORED**)
    - `load_on_startup=true`: Ensures that the wallet is automatically loaded in
      case of server restart

2. Create a new address
    ```shell
    # Save the output of this command
    bitcoin-cli getnewaddress
    ```

3. Obtain 33-byte BTC public key derived from the above address
    ```shell
    bitcoin-cli getaddressinfo <btc_address> | jq -r .pubkey
    ```

Notes:
- In case you used a non-default bitcoin home directory, also include the
  `-datadir=/path/to/bitcoin/home` flag in all the above `bitcoin-cli` commands.
- The BTC public key of the covenant should be included in the global
  parameters of the network you operate in order for your covenant emulator to
  be included in the committee.

### 3.2. Unlock the wallet

The Covenant Signer expects that the bitcoind Offline Wallet is unlocked when
trying to contact it. To this end, you'll need to manually unlock the wallet
before proceeding with the Covenant Signer setup.

To unlock the wallet, execute the following command:

```shell
bitcoin-cli walletpassphrase "<passphrase>" <unlock_time>
```

where:
- `passphrase`: The wallet passphrase specified during the wallet creation step
- `unlock_time`: How long (**in seconds**) the wallet will remain unlocked for

Notes:
- You can either unlock the wallet for a long period of time, or set up an
  automation to unlock it periodically for shorter time periods. In the latter
  case, the automation will require secure access to the wallet passphrase.
- In case of server restart, the wallet will need to be unlocked again.

### 3.3. Back-up the wallet

For the bitcoind wallet, bitcoin-level backups can also be obtained through the
following process.

```shell
# Backup the wallet
bitcoin-cli -rpcwallet=<wallet-name> backupwallet /path/to/backup/wallet.dat
# Restore the wallet
bitcoin-cli restorewallet <wallet-name> /path/to/backup/wallet.dat
```

*Note*: We recommend creating multiple backups of the wallet and
storing them in separate places.

## 4. Covenant Signer setup

### 4.1. Hardware Requirements

- An instance with at least 4G RAM and 2 vCPUs is expected
- The component can be horizontally scaled with traffic being load-balanced
  behind a reverse proxy

### 4.2. Network Requirements

- The Covenant Signer is publicly reachable on the configured server port
- The port accepts only TLS traffic (can be achieved by exposing the Covenant
  Signer through a reverse proxy)
- Ideally, the Covenant Signer is also protected against DDoS attacks

### 4.3. Installation

#### Prerequisites

This project requires Go version 1.21 or later.

Install Go by following the instructions on the official Go installation guide.

#### Download the code

To get started, clone the repository to your local machine from GitHub; please
use the version according to the phase-1 system guidelines --
you can find all versions in the official
[releases](https:/github.com/babylonchain/covenant-signer-private/releases) page.

```shell
git clone https://github.com/babylonchain/covenant-signer-private.git
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

### 4.4. Configuration

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
# Btc network (testnet3|mainnet|regtest|signet)
network = <btc_network>

#### Parameters related to the bitcoind wallet
[btc-signer-config]
# Btc node host
host = <bitcoind_wallet_endpoint>
# Btc node user
user = <bitcoind_wallet_username>
# Btc node password
pass = <bitcoind_wallet_password>
# Btc network (testnet3|mainnet|regtest|signet)
network = <btc_network>

#### Parameters related to the Covenant Signer server
[server-config]
# The address to listen on
host = "127.0.0.1"
# The port to listen on
port = 9791

#### Parameters related to the Prometheus metrics server
[metrics]
# The prometheus server host
host = "127.0.0.1"
# The prometheus server port
port = 2112
```

The Covenant Signer also consumes an additional configuration file containing
global parameters (`global-params.json`), i.e. parameters which are shared
between several services of the Babylon BTC Staking system. The file resides
under the same directory as `config.toml`.

The global parameters can be obtained from the parameters registry
found [here](https://github.com/babylonchain/networks/). The parameters will be
fully specified once all covenant committee participants share their keys.

### 4.5. Boot

To start the Covenant Signer, execute the following:

```shell
covenant-signer start --config /path/to/signer/home/config.toml \
    --params /path/to/signer/home/global-params.toml
```

Post-boot, the following log is emitted:

```shell
{"level":"info","time":"2024-05-07T17:16:18Z","message":"Starting server on 0.0.0.0:9791"}
```

A successful signing request emits the following log pair:

```shell
{"level":"debug","path":"/v1/sign-unbonding-tx","traceId":"5b1872eb-6ec6-4d05-bbc9-f88728e3fb72","time":"2024-05-07T19:01:40Z","message":"request received"}
{"level":"info","path":"/v1/sign-unbonding-tx","traceId":"5b1872eb-6ec6-4d05-bbc9-f88728e3fb72","tracingInfo":{"SpanDetails":null},"requestDuration":42,"time":"2024-05-07T19:01:40Z","message":"Request completed"}
```

### 4.6. Monitoring

#### Built-in Prometheus metrics

The service exposes Prometheus metrics through a Prometheus server. By default,
the server is reachable under `127.0.0.1:2112`.

The following metrics are exposed:
- `signer_received_signing_requests`: The total number of signing requests
  received by the server
- `signer_succeeded_signing_requests`: The total number times the signer
  successfully responded with a signature
- `signer_failed_signing_requests`: The total number of times signer responded
  with an internal error

These metrics can be scraped by a Prometheus instance.

A simple Prometheus alerting rule to check for failed signing request follows
below:

```shell
signer_failed_signing_requests - signer_failed_signing_requests offset 60m > 0
```

#### HTTP Healthchecks

Healthchecks should be configured on the `/v1/sign-unbonding-tx` server HTTP
endpoint. By default, the server is reachable under `127.0.0.1:9791`.

One approach to perform HTTP/S healthchecks and expose results in the form of
Prometheus metrics is the
[Prometheus Blackbox Exporter](https://github.com/prometheus/blackbox_exporter).

These metrics can then be scraped by a Prometheus instance.
