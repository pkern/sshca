/*
Copyright © 2024 Philipp Kern <pkern@debian.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"os"

	"github.com/pkern/sshca/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "sshca",
	Short: "Ad-hoc SSH certificate authority",
	Long: `sshca can be used behind an SSH ForcedCommand to issue short-lived
certificates to users. It is commonly used like this in authorized_keys
of a role account:

restrict,command="sshca run <username>" ssh-rsa [...]

It will take a JSON-encoded request on stdin and output a JSON structure
containing a certificate to stdout.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

var (
	cfgFile        string
	signingKeyFile string
)

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.sshca.toml)")
	rootCmd.PersistentFlags().StringVar(&signingKeyFile, "signing-key", "", "signing key file")
	viper.BindPFlag("signing_key_filename", rootCmd.PersistentFlags().Lookup("signing-key"))
}

var policy config.Policy

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("toml")
		viper.SetConfigName(".sshca")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			cobra.CheckErr(err)
		}
	}

	policy = &config.AdminOnlyPolicy{}
}
