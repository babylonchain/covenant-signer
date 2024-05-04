package signerapp

import (
	"bytes"
	"context"
	"fmt"
	"github.com/babylonchain/babylon/btcstaking"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type SpendPathDescription struct {
	ControlBlock *txscript.ControlBlock
	ScriptLeaf   *txscript.TapLeaf
}

type SigningRequest struct {
	StakingOutput        *wire.TxOut
	UnbondingTransaction *wire.MsgTx
	CovenantPublicKey    *btcec.PublicKey
	CovenantAddress      btcutil.Address
	SpendDescription     *SpendPathDescription
}

type SigningResult struct {
	Signature *schnorr.Signature
}

type ExternalBtcSigner interface {
	RawSignature(ctx context.Context, request *SigningRequest) (*SigningResult, error)
}

type TxInfo struct {
	Tx                *wire.MsgTx
	TxInclusionHeight uint32
}

type BtcChainInfo interface {
	// Returns only transactions inluded in canonical chain
	// passing pkScript as argument make it light client friendly
	TxByHash(ctx context.Context, txHash *chainhash.Hash, pkScript []byte) (*TxInfo, error)

	BestBlockHeight(ctx context.Context) (uint32, error)
}

type BabylonParams struct {
	CovenantPublicKeys []*btcec.PublicKey
	CovenantQuorum     uint32
	MagicBytes         []byte
	W                  uint32
	UnbondingTime      uint16
	UnbondingFee       btcutil.Amount
}

type BabylonParamsRetriever interface {
	Params(ctx context.Context) (*BabylonParams, error)
}

type SignerApp struct {
	s   ExternalBtcSigner
	r   BtcChainInfo
	p   BabylonParamsRetriever
	net *chaincfg.Params
}

func NewSignerApp(
	s ExternalBtcSigner,
	r BtcChainInfo,
	p BabylonParamsRetriever,
	net *chaincfg.Params,
) *SignerApp {
	return &SignerApp{
		s:   s,
		r:   r,
		p:   p,
		net: net,
	}
}

func (s *SignerApp) pubKeyToAddress(pubKey *btcec.PublicKey) (btcutil.Address, error) {
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	witnessAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		pubKeyHash, s.net,
	)

	if err != nil {
		return nil, err
	}
	return witnessAddr, nil
}

func outputsAreEqual(a *wire.TxOut, b *wire.TxOut) bool {
	if a.Value != b.Value {
		return false
	}

	if !bytes.Equal(a.PkScript, b.PkScript) {
		return false
	}

	return true
}

func (s *SignerApp) SignUnbondingTransaction(
	ctx context.Context,
	stakingOutputPkScript []byte,
	unbondingTx *wire.MsgTx,
	covnentSignerPubKey *btcec.PublicKey,
) (*schnorr.Signature, error) {
	if err := btcstaking.IsSimpleTransfer(unbondingTx); err != nil {
		return nil, err
	}

	script, err := txscript.ParsePkScript(stakingOutputPkScript)

	if err != nil {
		return nil, err
	}

	if script.Class() != txscript.WitnessV1TaprootTy {
		return nil, fmt.Errorf("invalid staking output pk script")
	}

	stakingTxHash := unbondingTx.TxIn[0].PreviousOutPoint.Hash

	stakingTxInfo, err := s.r.TxByHash(ctx, &stakingTxHash, stakingOutputPkScript)

	if err != nil {
		return nil, err
	}

	bestBlock, err := s.r.BestBlockHeight(ctx)

	if err != nil {
		return nil, err
	}

	// TODO: This should probably be done when service is started, otherwise if we implement
	// retrieving params from service we will call it for every signing request
	params, err := s.p.Params(ctx)

	if err != nil {
		return nil, err
	}

	if bestBlock-stakingTxInfo.TxInclusionHeight < params.W {
		return nil, fmt.Errorf("staking tx is not mature")
	}

	parsedStakingTransaction, err := btcstaking.ParseV0StakingTx(
		stakingTxInfo.Tx,
		params.MagicBytes,
		params.CovenantPublicKeys,
		params.CovenantQuorum,
		s.net)

	if err != nil {
		return nil, err
	}

	expectedUnbondingOutputValue := parsedStakingTransaction.StakingOutput.Value - int64(params.UnbondingFee)

	if expectedUnbondingOutputValue <= 0 {
		// This is actually eror of our parameters configuaration and should not happen
		// for honest requests.
		return nil, fmt.Errorf("staking output value is too low")
	}

	// build expected output in unbonding transaction
	unbondingInfo, err := btcstaking.BuildUnbondingInfo(
		parsedStakingTransaction.OpReturnData.StakerPublicKey.PubKey,
		[]*btcec.PublicKey{parsedStakingTransaction.OpReturnData.FinalityProviderPublicKey.PubKey},
		params.CovenantPublicKeys,
		params.CovenantQuorum,
		params.UnbondingTime,
		btcutil.Amount(expectedUnbondingOutputValue),
		s.net,
	)

	if err != nil {
		return nil, err
	}

	if !outputsAreEqual(unbondingInfo.UnbondingOutput, unbondingTx.TxOut[0]) {
		return nil, fmt.Errorf("unbonding output does not match expected output")
	}

	// At this point we know that:
	// - unbonding tx has correct shape - 1 input, 1 output, no timelocks, not replaceable
	// - staking tx exists on btc chain, is mature and has correct shape according Babylong Params
	// - unbonding tx output matches the parameters from the staking transaction and the params
	// We can send request to our remote signer

	stakingInfo, err := btcstaking.BuildStakingInfo(
		parsedStakingTransaction.OpReturnData.StakerPublicKey.PubKey,
		[]*btcec.PublicKey{parsedStakingTransaction.OpReturnData.FinalityProviderPublicKey.PubKey},
		params.CovenantPublicKeys,
		params.CovenantQuorum,
		parsedStakingTransaction.OpReturnData.StakingTime,
		btcutil.Amount(parsedStakingTransaction.StakingOutput.Value),
		s.net,
	)

	if err != nil {
		return nil, err
	}

	unbondingPathInfo, err := stakingInfo.UnbondingPathSpendInfo()

	if err != nil {
		return nil, err
	}

	covenantKeyAddress, err := s.pubKeyToAddress(covnentSignerPubKey)

	if err != nil {
		return nil, err
	}

	sig, err := s.s.RawSignature(ctx, &SigningRequest{
		StakingOutput:        parsedStakingTransaction.StakingOutput,
		UnbondingTransaction: unbondingTx,
		CovenantPublicKey:    covnentSignerPubKey,
		CovenantAddress:      covenantKeyAddress,
		SpendDescription: &SpendPathDescription{
			ControlBlock: &unbondingPathInfo.ControlBlock,
			ScriptLeaf:   &unbondingPathInfo.RevealedLeaf,
		},
	})

	if err != nil {
		return nil, err
	}

	return sig.Signature, nil
}
