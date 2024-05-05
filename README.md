# Covenant Signer

The covenant signer is a standalone program operating a server
that accepts requests for signing transactions that require covenant emulation.
It is operated by members of the covenant emulation committee and
accessed to collect signatures of Bitcoin Staking on-demand unbonding
transactions.

## Background

The Bitcoin Staking protocol introduces the ability for Bitcoin holders to lock
their Bitcoin in a self-custodial Bitcoin Staking Script in order to get voting
power in a Bitcoin secured PoS protocol.
Among others, the
[Bitcoin Staking Script](https://github.com/babylonchain/babylon/blob/v0.8.5/docs/staking-script.md)
involves a pre-defined timelock for which the stake remains active.
To enable a user experience comparable to typical PoS systems,
the script allows for the stake to be on-demand unlocked prior to the timelock
expiration. However, due to the limited expressiveness of the Bitcoin scripting
language, a covenant emulation committee is required to co-sign unbonding
transactions in order to ensure that the stake is unlocked in a protocol
compliant way. More specifically, the covenant emulation committee is
responsible for verifying on-demand unbonding transactions and if they are
valid, providing its signatures for them.
If a quorum of the members of the covenant emulation committee provide their
signatures, then the on-demand unbonding transaction is fully signed and can be
propagated to the network. More details on the need for covenants and the
covenant committee can be found
[here](https://github.com/babylonchain/covenant-emulator/blob/v0.1.0/README.md).

## Covenant Signer Server

### Requirements

The design of the covenant signer server is guided by the following
requirements:
- *High Availability*: The signers should be highly available as unbonding
  requests may arrive at any time.
- *Secure Storage of Keys*: The private key of the covenant emulator committee
  member should be encrypted when stored on disk to mitigate the risk of theft.
- *Backed up Keys*: The private key of the covenant emulator committee member
  should be easy to back-up to mitigate the risk of loss.

### Prior Work

The covenant signer server design is based on the following documents:
- [Bitcoind: Managing the Wallet](https://github.com/bitcoin/bitcoin/blob/master/doc/managing-wallets.md)
- [Bitcoind: Offline Signing Tutorial](https://github.com/bitcoin/bitcoin/blob/master/doc/offline-signing-tutorial.md)
- [Lightning: Remote Signing](https://github.com/lightningnetwork/lnd/blob/master/docs/remote-signing.md)

### Architecture

![architecture](/docs/architecture.png)

To fulfill the above requirements, the covenant signer server has been designed
to consist of the following components:
- *Signing Server* - functions as a server receiving signing requests. It has
  no access to the private key and it is connected to the internet.
- *Bitcoind instance in wallet mode* - a bitcoind instance that stores the
  covenant emulator committee member's key. This instance should be located in
  a secure network and only allow connections from the signing server
  component. Bitcoind was chosen as the signing-backend as it is an easy-to-use
  and open source software which has been heavily tested in adversarial
  environments.

> Note: The covenant-signer server is a sibling program of the [covenant
> emulator](https://github.com/babylonchain/covenant-emulator). The main
> difference between the two programs is that the covenant-signer functions as
> a server accepting signing requests, while the covenant-emulator functions as
> a daemon reading for transactions that are pending covenant signatures from a
> Babylon node. The covenant-signer is used in systems in which there is no
> underlying Babylon chain to read from.


## Deployment

The [Deployment](/docs/deployment.md) document covers instructions on
the secure set up of the covenant signer server.
