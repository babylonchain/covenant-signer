package config

type SignerConfig struct {
	StakingTxConfirmationDepth uint32 `mapstructure:"staking-tx-confirmation-depth"`
}

func DefaultSignerConfig() *SignerConfig {
	return &SignerConfig{
		StakingTxConfirmationDepth: 6,
	}
}
