# Design of secure covenant signing system

## Context

Covenant committee is a group of signers approving un-bonding transactions
(and in later phases slashing transactions).
You can find more details about the need for a covenant committee
in this [document](https://github.com/babylonchain/covenant-emulator/blob/v0.1.0/README.md).
Stakers that want to un-bond their delegations before the timelock expires need to gather
enough covenant signatures to reach the quorum required in the un-bonding path of
the Bitcoin staking transaction output.

This means that covenant committee members need to listen for un-bonding requests
from stakers, and provide signatures for valid un-bonding transactions.

Covenant committee members must not sign any transactions which do not obey
Babylon system rules, for example, un-bonding transactions without timelock.
It is imperative that they protect their private keys, as they are critical
for correct system functioning. Their keys should stored in an encrypted format, and
must be properly backed up.


## Requirements

Requirements for secure signer:

1. Signers should be highly available. This is needed, as un-bonding requests
may arrive at any time.
2. The private key of the signer should be encrypted when stored on disk.
This ensures that even if the machine with the private key is compromised,
the private key won’t leak.
3. It should be easy to back-up the private key to protect against key loss.
Losing the private key, means that the covenant committee member must be
rotated outside of the covenant committee set.
4. Signer should be able to sign BTC transactions. This is needed as covenant
committee members will not be signing arbitrary data, but BTC transactions which
have their own rules for signing.

## Required reading

The secure covenant signer design is based on the following documents:
- [Bitcoind: Managing the Wallet](https://github.com/bitcoin/bitcoin/blob/master/doc/managing-wallets.md)
- [Bitcoind: Offline Signing Tutorial](https://github.com/bitcoin/bitcoin/blob/master/doc/offline-signing-tutorial.md)
- [Lightning: Remote Signing](https://github.com/lightningnetwork/lnd/blob/master/docs/remote-signing.md)

## High level overview

![diagram](/docs/diagram.png)

To fulfill all the design requirements,
this doc proposes the split of the covenant signer system into two parts:
- *Signing server* - a component which will function
as server receiving signing requests and
will have no or minimal access to covenant private key.
- *Bitcoind instance in wallet mode* - a bitcoind instance
that will be store the covenant committee member's key.
This instance should be located in a secured network, and
only allow connections from the signing server component.

### Why bitcoind as initial signing Backend ?

Bitcoind was chosen as the signing back-end
as it is open source software which has been heavily tested in
adversarial environments.
It has an easy to use CLI interface for creating, encrypting and
back-uping managed wallets.
These qualities make it a good choice for a signing backend.


## System Details

### Connection between Signing server and Bitcoin instance

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


### Creating signatures

#### Using PSBTs

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

#### Using private key directly

This is a less secure way that should be used only for testing purposes.
In it, the signing server:
1. retrieves the private key from the Bitcoind instance
and loads it into the memory
2. signs the request using imported bitcoin libraries
3. eliminates the key from the memory

This version of signing should only be used on testnets.

### Wallet operations

To create encrypted wallet:

`$ bitcoin-cli -named createwallet wallet_name="wallet-01" passphrase="passphrase"`

To backup a wallet:

`$ bitcoin-cli -rpcwallet="wallet-01" backupwallet /home/node01/Backups/backup-01.dat`

To restore wallet from backup:

`$ bitcoin-cli restorewallet "restored-wallet" /home/node01/Backups/backup-01.dat`

### Creation of Covenant key

After creation of encrypted wallet call:

`bitcoin-cli -rpcwallet=<wallet_name> getnewaddress`

This will generate new Bitcoin address (by default p2wpkh) and new public key
corresponding to this address.

Next call:

`bitcoin-cli -rpcwallet=<wallet_name> getaddressinfo "addressFromStep1"`

Response (https://developer.bitcoin.org/reference/rpc/getaddressinfo.html ) will
contain `pubkey` field which contains hex encoded public key.
This key can become covenant public key.

