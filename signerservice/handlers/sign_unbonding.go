package handlers

import (
	"encoding/hex"
	"encoding/json"
	"github.com/babylonchain/covenant-signer/signerservice/types"
	"github.com/babylonchain/covenant-signer/utils"
	"github.com/btcsuite/btcd/btcec/v2"
	"net/http"
)

func (h *Handler) SignUnbonding(request *http.Request) (*Result, *types.Error) {
	payload := &types.SignUnbondingTxRequest{}
	err := json.NewDecoder(request.Body).Decode(payload)
	if err != nil {
		return nil, types.NewErrorWithMsg(http.StatusBadRequest, types.BadRequest, "invalid request payload")
	}

	pkScript, err := hex.DecodeString(payload.StakingOutputPkScriptHex)

	if err != nil {
		return nil, types.NewErrorWithMsg(http.StatusBadRequest, types.BadRequest, "invalid staking output pk script")
	}

	covenantPublicKeyBytes, err := hex.DecodeString(payload.CovenantPublicKey)

	if err != nil {
		return nil, types.NewErrorWithMsg(http.StatusBadRequest, types.BadRequest, "invalid covenant public key")
	}

	covenantPublicKey, err := btcec.ParsePubKey(covenantPublicKeyBytes)

	if err != nil {
		return nil, types.NewErrorWithMsg(http.StatusBadRequest, types.BadRequest, "invalid covenant public key")
	}

	unbondingTx, _, err := utils.NewBTCTxFromHex(payload.UnbondingTxHex)

	if err != nil {
		return nil, types.NewErrorWithMsg(http.StatusBadRequest, types.BadRequest, "invalid unbonding transaction")
	}

	sig, err := h.s.SignUnbondingTransaction(
		request.Context(),
		pkScript,
		unbondingTx,
		covenantPublicKey,
	)

	if err != nil {
		// TODO Properly translate errors between layers
		return nil, types.NewErrorWithMsg(http.StatusInternalServerError, types.InternalServiceError, err.Error())
	}

	resp := types.SignUnbondingTxResponse{
		SignatureHex: hex.EncodeToString(sig.Serialize()),
	}

	return NewResult(resp), nil
}
