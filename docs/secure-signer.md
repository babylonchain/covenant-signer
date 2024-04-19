# Design of secure covenant signing system

## Context

Covenant committee is a group of signers approving un-bonding transactions.
(and in later phases slashing transactions)
Staker wanting to un-bond his delegation before timelock expires needs to gather
enough covenant signatures to reach the quorum required in un-bonding path of his
staking output.

This means that covenant committee members need to listen for un-bonding requests
from stakers, and provide signatures for valid un-bonding transactions.

Covenant committee members must not sign any transactions which do not obey
Babylon system rules, for example, un-bonding transactions without timelock.

Covenant committee members must also protect their private keys, as those critical
for correct system functioning. Keys should be stored in encrypted format, and
must have proper backups.


## Requirements

Requirements for secure signer:

1. Signers should be highly available. This is needed, as un-bonding requests
may arrive at any time.
2. Private key of signer should be encrypted when stored on disk. This is need
to ensure that even if machine with private key will be compromised private key
won’t leak.
3. It should be easy to create backup-up of private key. This is need as losing
private key is failure scenario, which require rotating covenant member key
4. Signer should be able to sign BTC transactions. This is needed as covenant
committee members will not be signing arbitrary data, but BTC transactions which
have their own rules of signing.

## Required reading

Following design will be based on following documents:

https://github.com/bitcoin/bitcoin/blob/master/doc/managing-wallets.md

https://github.com/bitcoin/bitcoin/blob/master/doc/offline-signing-tutorial.md

https://github.com/lightningnetwork/lnd/blob/master/docs/remote-signing.md


## High level overview

![diagram](/docs/diagram.png)

To fulfill all requirements, design in this doc propses to split covenant-signer
system into two part:
- Signing server - component which will be open to incoming signing requests and
will have no or minimal access to covenant private key.
- Bitcoind instance in wallet mode - this bitcoind instance will be responsible
for storing covenant member key. This instance should be located in secured
network, and allow connection only from Signing server.

### Why bitcoind as initial signing Backend ?

Bitcoind node is open source software which is heavily used in adversarial
environment. It has easy to use cli interface for creating, encrypting and
back-uping managed wallets. All this qualites makes it good choice for initial
signing backend.


## Details

### Connection between Signing server and Bitcoin instance

Only component open to the interner is Signing Server which listens for
signing requests. It can be further hidden behind reverse proxy like ngnix.

Bitcoind instance in diagram must have all the p2p connections disabled. It
doesn’t need to have a blockchain copy. It should allow  connections only
from signing server.

Bitcoind instance should have rpc-server enabled. Ways of securing this json-rpc
connection are nicely described in https://github.com/bitcoin/bitcoin/blob/master/doc/JSON-RPC-interface.md#security

Connection between bitcoind instance and signing server must be over encrypted
channel.


### Creating signatures

#### Using psbt's

To create signature signing server will be using [walletprocesspsbt](
https://developer.bitcoin.org/reference/rpc/walletprocesspsbt.html#walletprocesspsbt)
bitcoind endpoint.

Minimal data required to create valid psbt to sign transaction spending taproot
input are:

1. output being spent
2. public key corresponding to private key which should sign given transaction.
It should be 33bytes compressed format.
3. control block required to spend given output. It contains: Internal public
key, proof of inclusion of script in given taproot output, and version of the
taproot leaf.
4. whole script from the script path being used

#### Using private key directly

This is less secure way, in which signing server:
- retrieves private key from bitcoind instance
- signs request using bitcoin libraries
- zero the key from the memory

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

