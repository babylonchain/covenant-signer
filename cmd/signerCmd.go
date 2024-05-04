package cmd

import (
	"github.com/babylonchain/covenant-signer/btcclient"
	"github.com/babylonchain/covenant-signer/config"
	"github.com/babylonchain/covenant-signer/signerapp"
	"github.com/babylonchain/covenant-signer/signerservice"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(runSignerCmd)
}

var runSignerCmd = &cobra.Command{
	Use:   "start",
	Short: "starts the signer service",
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := cmd.Flags().GetString(configPathKey)
		if err != nil {
			return err
		}
		cfg, err := config.GetConfig(path)
		if err != nil {
			return err
		}

		parsedConfig, err := cfg.Parse()

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

		paramsGetter := signerapp.NewConfigParamsRetriever(parsedConfig.ParamsConfig)

		app := signerapp.NewSignerApp(
			signer,
			chainInfo,
			paramsGetter,
			parsedConfig.BtcNodeConfig.Network,
		)

		srv, err := signerservice.New(
			cmd.Context(),
			parsedConfig,
			app,
		)

		if err != nil {
			return err
		}

		// TODO: Add signal handling and gracefull shutdown
		return srv.Start()
	},
}
