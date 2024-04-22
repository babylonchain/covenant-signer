package signerapp

import (
	"context"

	"github.com/babylonchain/covenant-signer/config"
)

var _ BabylonParamsRetriever = (*ConfigParamsRetriever)(nil)

type ConfigParamsRetriever struct {
	params *config.ParsedParamsConfig
}

func NewConfigParamsRetriever(params *config.ParsedParamsConfig) *ConfigParamsRetriever {
	return &ConfigParamsRetriever{
		params: params,
	}
}

func (c *ConfigParamsRetriever) Params(ctx context.Context) (*BabylonParams, error) {
	return &BabylonParams{
		CovenantPublicKeys: c.params.CovenantPublicKeys,
		CovenantQuorum:     c.params.CovenantQuorum,
		MagicBytes:         c.params.MagicBytes,
		W:                  c.params.W,
		UnbondingTime:      c.params.UnbondingTime,
		UnbondingFee:       c.params.UnbondingFee,
	}, nil
}
