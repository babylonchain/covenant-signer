# Covenant Signer Server Deployment

This document covers details about the setup and deployment of the covenant
signer server.

## Connection between Signing Server and Bitcoind Instance

The only component that is open for external connections
is the Signing Server.
One can decide to make it only accessible through a reverse proxy
such as Nginx.
The Bitcoind instance only functions in wallet mode, i.e. it does not need
to have a copy of the Bitcoin ledger.
It communicates with Signing Server component through RPC and,
to ensure safety,
it should only allow connections from it through an encrypted channel.
Additional measures for safety
include disabling all p2p connections and
securing the JSON-RPC connection through the mechanisms described
[here](https://github.com/bitcoin/bitcoin/blob/master/doc/JSON-RPC-interface.md#security)


## Signature Generation

### Using PSBTs

To create a signature the signing server will be using the [walletprocesspsbt](
https://developer.bitcoin.org/reference/rpc/walletprocesspsbt.html#walletprocesspsbt)
Bitcoind JSON-RPC endpoint.

The minimal data required to create a valid PSBT that signs a transaction spending a taproot

1. output being spent
2. public key corresponding to the private key which should sign the given transaction.
It should be 33bytes compressed format.
3. control block required to spend given output. It contains: Internal public
key, proof of inclusion of script in given taproot output, and version of the
taproot leaf.
4. whole script from the script path being used

### Using private key directly

This is a less secure way that should be used only for testing purposes.
In it, the signing server:
1. retrieves the private key from the Bitcoind instance
and loads it into the memory
2. signs the request using imported bitcoin libraries
3. eliminates the key from the memory

This version of signing should only be used on testnets.

## Wallet Setup

To create encrypted wallet:

`$ bitcoin-cli -named createwallet wallet_name="wallet-01" passphrase="passphrase"`

To backup a wallet:

`$ bitcoin-cli -rpcwallet="wallet-01" backupwallet /home/node01/Backups/backup-01.dat`

To restore wallet from backup:

`$ bitcoin-cli restorewallet "restored-wallet" /home/node01/Backups/backup-01.dat`

## Creation of Covenant key

After creation of encrypted wallet call:

`bitcoin-cli -rpcwallet=<wallet_name> getnewaddress`

This will generate new Bitcoin address (by default p2wpkh) and new public key
corresponding to this address.

Next call:

`bitcoin-cli -rpcwallet=<wallet_name> getaddressinfo "addressFromStep1"`

Response (https://developer.bitcoin.org/reference/rpc/getaddressinfo.html ) will
contain `pubkey` field which contains hex encoded public key.
This key can become covenant public key.
