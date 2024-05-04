package signerservice

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/babylonchain/covenant-signer/signerservice/handlers"
	"github.com/babylonchain/covenant-signer/signerservice/types"
	"io"
	"net/http"
	"time"

	"github.com/babylonchain/covenant-signer/utils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
)

func RequestCovenantSignaure(
	ctx context.Context,
	signerUrl string,
	timeout time.Duration,
	unbondingTx *wire.MsgTx,
	covenantMemberPublicKey *btcec.PublicKey,
	stakingTransactionPkScript []byte,
) (*schnorr.Signature, error) {
	unbondingTxHex, err := utils.SerializeBTCTxToHex(unbondingTx)

	if err != nil {
		return nil, err
	}

	keyHex := hex.EncodeToString(covenantMemberPublicKey.SerializeCompressed())

	pkScriptHex := hex.EncodeToString(stakingTransactionPkScript)

	req := types.SignUnbondingTxRequest{
		StakingOutputPkScriptHex: pkScriptHex,
		UnbondingTxHex:           unbondingTxHex,
		CovenantPublicKey:        keyHex,
	}

	marshalled, err := json.Marshal(req)

	if err != nil {
		return nil, err
	}

	route := fmt.Sprintf("%s/v1/sign-unbonding-tx", signerUrl)

	httpRequest, err := http.NewRequestWithContext(ctx, "POST", route, bytes.NewReader(marshalled))

	if err != nil {
		return nil, err
	}

	// use json
	httpRequest.Header.Set("Content-Type", "application/json")

	client := http.Client{Timeout: timeout}
	// send the request
	res, err := client.Do(httpRequest)

	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	defer res.Body.Close()
	// read body
	resBody, err := io.ReadAll(res.Body)

	if err != nil {
		return nil, err
	}

	var response handlers.PublicResponse[types.SignUnbondingTxResponse]
	if err := json.Unmarshal(resBody, &response); err != nil {
		return nil, err
	}

	return utils.SchnorSignatureFromHex(response.Data.SignatureHex)
}
