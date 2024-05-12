# Covenant Signer request/response handling

This document covers the request/response data format for the covenant signer.
It also describes validation processes required to establish
whether the received unbonding request is valid.


## Signing Request

Valid signing request contains the following JSON payload:

```json
{
  "staking_output_pk_script_hex": "pk_script_hex",
  "unbonding_tx_hex": "unbonding_tx_hex",
  "staker_unbonding_sig_hex": "staker_unbonding_sig_hex",
  "covenant_public_key": "covenant_public_key"
}
```
where:
`staking_output_pk_script_hex` - 34byte hex encoded pk script of staking output
from staking transaction which is being un-bonded
`unbonding_tx_hex` - hex encoded btc serialized un-bonding transaction which
should be signed
`staker_unbonding_sig_hex` - hex encoded 64byte Schnorr signature of Staker
over the un-bonding transaction
`covenant_public_key` - hex encoded 33byte (compressed format) public key
of covenant member which must create the signature


## Signing Response

The response to a valid signing request will contain the following JSON payload:

```json
{
  "signature_hex": "signature_hex",
}
```

where:
`signature_hex` - 64byte hex encoded Schnorr signature over the un-bonding
transaction using un-bonding path, made by the covenant emulator committee member.

## Validation of Signing request
Given data received:
- `unbonding_tx`
- `staking_output_pk_script`
- `staker_unbonding_sig`
- `covenant_pk`

Functions provided by Babylon staking package -
`"github.com/babylonchain/babylon/btcstaking"`:
- `ParseV0StakingTx(staking_tx, tag, covenant_keys, covenant_quorum, btc_network)`
- `BuildUnbondingInfo(staker_pk, fp_pk, covenant_keys, covenant_quorum, unbonding_time, unbonding_value, btc_network)`
- `BuildStakingInfo(staker_pk, fp_pk, covenant_keys, covenant_quorum, staking_time, staking_value, btc_network)`
- `VerifyTransactionSigWithOutput(transaction, funding_output, script, public_key, signature)`

Operating on:
- `current_btc_network`


Following steps must be taken to validate incoming signing request:
1. Check that all data in the request has expected number of bytes, and correctly
de-serializes to expected objects.
2. Check that un-bonding transaction has correct the shape
  - `len(unbonding_tx.inputs) == 1`
  - `len(unbonding_tx.outputs) == 1`
  - `unbonding_tx.LockTime = 0`
  - `unbonding_tx.inputs[0].Sequence = 0xffffffff`
3. Check that `is_taproot_pk_script(staking_output_pk_script) == true`
4. Retrieve from the btc ledger the `staking_tx` corresponding to the `unbonding_tx`,
such that `staking_tx.hash() == unbonding_tx.inputs[0].previous_outpoint.hash`.
5. Retrieve `global_parameters` applicable at height in which `staking_tx` is
included in btc ledger.
6. Check that `depth_in_btc_ledger(staking_tx) >= global_parameters.confirmation_depth`
7. Call `ParseV0StakingTx` with following data:
- `staking_tx`
- `global_parameters.magic_bytes`
- `global_parameters.covenant_keys`
- `global_parameters.covenant_quorum`
- `current_btc_network`
8. Previous check should parse values from `staking_tx`: `staker_pk`, `fp_pk`
`staking_output_index`,`staking_value` and `staking_time`
9. Check that `staking_output_index == unbonding_tx.inputs[0].previous_outpoint.index`
10. Check that:
 - `global_parameters.min_staking_value <= staking_value && staking_value <= global_parameters.min_staking_value`
 - `global_parameters.min_staking_time <= staking_time && staking_time <= global_parameters.max_staking_time`
11. Call `BuildUnbondingInfo` with following values:
- `staker_pk`
- `fp_pk`
- `global_parameters.covenant_keys`
- `global_parameters.covenant_quorum`
- `global_parameters.unbonding_time`
- `staking_value - global_parameters.unbonding_fee`
- `current_btc_network`

  to build `expected_output`
12. Check `unbonding_tx.output == expected_output` matches `expected_output`
13. Call `BuildStakingInfo` with following values:
- `staker_pk`
- `fp_pk`
- `global_parameters.covenant_keys`
- `global_parameters.covenant_quorum`
- `staking_time`
- `staking_value`
- `current_btc_network`

  to build orignal `unbonding_script`
14. Call `VerifyTransactionSigWithOutput` with following data:
- `unbonding_tx`
- `staking_tx.outputs[staking_output_index]`
- `unbonding_script`
- `staker_pk`
- `staker_unbonding_sig`

  to verify staker signature over un-bonding transaction

After all validations succeed create valid Schnnor signature over `unbonding_tx`
and return it to the caller.
