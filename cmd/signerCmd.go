package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/babylonchain/covenant-signer/btcclient"
	"github.com/babylonchain/covenant-signer/config"
	m "github.com/babylonchain/covenant-signer/observability/metrics"
	"github.com/babylonchain/covenant-signer/signerapp"
	"github.com/babylonchain/covenant-signer/signerservice"
)

func init() {
	rootCmd.AddCommand(runSignerCmd)
}

var runSignerCmd = &cobra.Command{
	Use:   "start",
	Short: "starts the signer service",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, err := cmd.Flags().GetString(configPathKey)
		if err != nil {
			return err
		}
		cfg, err := config.GetConfig(configPath)
		if err != nil {
			return err
		}

		parsedConfig, err := cfg.Parse()

		if err != nil {
			return err
		}

		parsedGlobalParams, err := signerapp.NewVersionedParamsRetriever(globalParamPath)

		if err != nil {
			return err
		}

		fullNodeClient, err := btcclient.NewBtcClient(parsedConfig.BtcNodeConfig)

		if err != nil {
			return err
		}

		chainInfo := signerapp.NewBitcoindChainInfo(fullNodeClient)

		signerClient, err := btcclient.NewBtcClient(parsedConfig.BtcSignerConfig)

		if err != nil {
			return err
		}

		// TODO: Add options to use customn remote signers
		signer := signerapp.NewPsbtSigner(signerClient)

		app := signerapp.NewSignerApp(
			signer,
			chainInfo,
			parsedGlobalParams,
			parsedConfig.BtcNodeConfig.Network,
		)

		metrics := m.NewCovenantSignerMetrics()

		srv, err := signerservice.New(
			cmd.Context(),
			parsedConfig,
			app,
			metrics,
		)

		if err != nil {
			return err
		}

		metricsAddress := fmt.Sprintf("%s:%d", cfg.Metrics.Host, cfg.Metrics.Port)

		m.Start(metricsAddress, metrics.Registry)

		// TODO: Add signal handling and gracefull shutdown
		return srv.Start()
	},
}
