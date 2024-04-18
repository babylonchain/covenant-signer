package signerapp

import (
	"context"
	"fmt"

	staking "github.com/babylonchain/babylon/btcstaking"

	"github.com/babylonchain/covenant-signer/btcclient"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var _ ExternalBtcSigner = (*PsbtSigner)(nil)

type PsbtSigner struct {
	client *btcclient.BtcClient
}

func NewPsbtSigner(client *btcclient.BtcClient) *PsbtSigner {
	return &PsbtSigner{
		client: client,
	}
}

func (s *PsbtSigner) RawSignature(ctx context.Context, request *SigningRequest) (*SigningResult, error) {
	if err := staking.IsSimpleTransfer(request.UnbondingTransaction); err != nil {
		return nil, fmt.Errorf("invalid unbonding transaction: %w", err)
	}
	psbtPacket, err := psbt.New(
		[]*wire.OutPoint{&request.UnbondingTransaction.TxIn[0].PreviousOutPoint},
		request.UnbondingTransaction.TxOut,
		request.UnbondingTransaction.Version,
		request.UnbondingTransaction.LockTime,
		[]uint32{wire.MaxTxInSequenceNum},
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create PSBT packet with unbonding transaction: %w", err)
	}

	var covenantKeys psbt.Bip32Sorter
	// psbt.Bip32Sorter

	for _, key := range request.CovenantPublicKeys {
		k := key
		covenantKeys = append(covenantKeys, &psbt.Bip32Derivation{
			PubKey: k.SerializeCompressed(),
		})
	}

	fmt.Printf("There is %d covenant keys\n", len(covenantKeys))

	// sort.Sort(covenantKeys)
	//
	psbtPacket.Inputs[0].SighashType = txscript.SigHashDefault
	psbtPacket.Inputs[0].WitnessUtxo = request.StakingOutput
	psbtPacket.Inputs[0].Bip32Derivation = covenantKeys

	ctrlBlockBytes, err := request.SpendDescription.ControlBlock.ToBytes()

	if err != nil {
		return nil, fmt.Errorf("failed to serialize control block: %w", err)
	}

	psbtPacket.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: ctrlBlockBytes,
			Script:       request.SpendDescription.ScriptLeaf.Script,
			LeafVersion:  request.SpendDescription.ScriptLeaf.LeafVersion,
		},
	}

	fmt.Println("***************************************")
	fmt.Println("Before signing")
	fmt.Println(psbtPacket.Inputs[0])

	signedPacket, err := s.client.SignPsbt(psbtPacket)

	if err != nil {
		return nil, fmt.Errorf("failed to sign PSBT packet: %w", err)
	}

	fmt.Println("***************************************")
	fmt.Println("After signing")
	fmt.Println(signedPacket.Inputs[0])

	if len(signedPacket.Inputs[0].TaprootScriptSpendSig) == 0 {
		// this can happen if btcwallet does not maintain the private key for the
		// for the public in signing request
		return nil, fmt.Errorf("no signature found in PSBT packet. Wallet does not maintain covenant public key")
	}

	schnorSignature := signedPacket.Inputs[0].TaprootScriptSpendSig[0].Signature

	parsedSignature, err := schnorr.ParseSignature(schnorSignature)

	if err != nil {
		return nil, fmt.Errorf("failed to parse schnorr signature in psbt packet: %w", err)

	}

	result := &SigningResult{
		Signature: parsedSignature,
	}

	return result, nil
}
