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
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

func expandUser(val string) string {
	if u := os.Getenv("USER"); u != "" {
		val = strings.ReplaceAll(val, "$USER", u)
	}
	return val
}

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:          "get",
	Short:        "Get a certificate from the configured CA",
	Long:         `Requests a certificate from the configured CA and adds it to the agent.`,
	Args:         cobra.ExactArgs(0),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("could not generate ed25519 key: %w", err)
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			return fmt.Errorf("could not generate SSH public key: %w", err)
		}
		principals := viper.GetStringSlice("principals")
		if len(principals) == 0 {
			principals = []string{"$USER"}
		}
		for i, p := range principals {
			principals[i] = expandUser(p)
		}
		r, err := json.Marshal(&Request{
			Lifetime:   Duration(viper.GetDuration("lifetime")),
			Principals: principals,
			PublicKey:  string(ssh.MarshalAuthorizedKey(sshPub)),
		})
		if err != nil {
			return fmt.Errorf("could not marshal request: %w", err)
		}

		c := exec.Command("ssh", fmt.Sprintf("%s@%s", viper.GetString("ca_user"), viper.GetString("ca_host")), "-T")
		c.Stdin = bytes.NewBuffer(r)
		c.Stderr = os.Stderr
		stdout, err := c.Output()
		if err != nil {
			return fmt.Errorf("could not communicate with CA: %w", err)
		}
		var resp Response
		if err := json.Unmarshal(stdout, &resp); err != nil {
			return fmt.Errorf("could not unmarshal CA response: %w", err)
		}

		baseDir := path.Join(os.Getenv("XDG_RUNTIME_DIR"), "sshca")
		if err := os.MkdirAll(baseDir, 0700); err != nil {
			return fmt.Errorf("could not create local credential directory %q: %w", baseDir, err)
		}

		domain := viper.GetString("domain")
		privKeyPath := path.Join(baseDir, domain)
		f, err := os.OpenFile(privKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("could not create private key file %q: %w", privKeyPath, err)
		}
		block, err := ssh.MarshalPrivateKey(priv, fmt.Sprintf("SSHCA/%s authentication key (%s)", domain, time.Now().Format(timeFormat)))
		if err != nil {
			return fmt.Errorf("could not marshal private key: %w", err)
		}
		pem.Encode(f, block)
		if err := f.Close(); err != nil {
			return err
		}

		certPath := fmt.Sprintf("%s-cert.pub", privKeyPath)
		f, err = os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("could not create certificate file %q: %w", certPath, err)
		}
		f.WriteString(resp.Certificate)
		f.WriteString("\n")
		if err := f.Close(); err != nil {
			return err
		}

		stdout, err = exec.Command("ssh-add", "-L").Output()
		if exiterr, ok := err.(*exec.ExitError); (ok && exiterr.ExitCode() == 2) || (!ok && err != nil) {
			return fmt.Errorf("could not query the SSH agent for its keys: %w", err)
		}
		var remove bytes.Buffer
		for _, k := range bytes.Split(stdout, []byte("\n")) {
			if bytes.Contains(k, []byte(fmt.Sprintf("SSHCA/%s authentication key", domain))) {
				remove.Write(k)
				remove.Write([]byte("\n"))
			}
		}
		c = exec.Command("ssh-add", "-D")
		c.Stdin = &remove
		if err := c.Run(); err != nil {
			return fmt.Errorf("could not remove old authentication keys from the agent: %w", err)
		}

		c = exec.Command("ssh-add", privKeyPath)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return fmt.Errorf("could not insert key into agent: %w", err)
		}
		return nil
	},
}

func init() {
	getCmd.Flags().StringP("domain", "d", "example", "Name of the target trust domain")
	getCmd.Flags().String("ca-user", "sshca", "CA user to SSH to")
	getCmd.Flags().String("ca-host", "", "CA host to SSH to")
	getCmd.Flags().DurationP("lifetime", "t", 1*time.Hour, "Requested lifetime of the certificate")
	getCmd.Flags().StringSliceP("principals", "u", nil, "Requested target principals")
	viper.BindPFlag("domain", getCmd.Flags().Lookup("domain"))
	viper.BindPFlag("ca_user", getCmd.Flags().Lookup("ca-user"))
	viper.BindPFlag("ca_host", getCmd.Flags().Lookup("ca-host"))
	viper.BindPFlag("lifetime", getCmd.Flags().Lookup("lifetime"))
	viper.BindPFlag("principals", getCmd.Flags().Lookup("principals"))
	rootCmd.AddCommand(getCmd)
}
