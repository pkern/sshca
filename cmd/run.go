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
	"crypto"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/syslog"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkern/sshca/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

type Request struct {
	Principals []string

	Lifetime Duration

	// PublicKey is in SSH authorized_keys format (ssh-ed25519 [...])
	PublicKey string `json:"public_key"`
}

type Response struct {
	Certificate string
}

type Duration time.Duration

func (d *Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(*d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	du, err := time.ParseDuration(v)
	if err != nil {
		return err
	}
	*d = Duration(du)
	return nil
}

const (
	backdate        = 5 * time.Minute
	defaultLifetime = 1 * time.Hour
	timeFormat      = "2006-01-02 15:04:05 -0700"
)

var defaultExtensions = map[string]string{
	"permit-pty":              "",
	"permit-user-rc":          "",
	"permit-port-forwarding":  "",
	"permit-agent-forwarding": "",
	"permit-X11-forwarding":   "",
}

func loadSigningKey(filename string) (crypto.PrivateKey, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	priv, err := ssh.ParseRawPrivateKey(b)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:          "run USERNAME",
	Short:        "Run the CA for the specified user",
	Long:         `Reads a CA request from stdin and issues a certificate if the policy allows it.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		u, err := config.LookupUser(args[0])
		if err != nil {
			return fmt.Errorf("could not lookup user %q: %w", args[0], err)
		}

		h, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("could not load the issuing machine's hostname: %w", err)
		}

		// If ExposeAuthInfo is set in the sshd, record that information for
		// later audit logging. Missing information is not critical.
		var caller string
		if fn := os.Getenv("SSH_USER_AUTH"); fn != "" {
			info, err := os.ReadFile(fn)
			if err != nil {
				return fmt.Errorf("SSH_USER_AUTH was set, but file %q cannot be read: %w", fn, err)
			}
			pubkey, _, _, _, err := ssh.ParseAuthorizedKey(info)
			if err != nil {
				return fmt.Errorf("could not parse SSH_USER_AUTH file %q: %w", fn, err)
			}
			caller = ssh.FingerprintSHA256(pubkey)
		}

		var r Request
		if err := json.NewDecoder(os.Stdin).Decode(&r); err != nil {
			return fmt.Errorf("could not decode JSON request: %w", err)
		}

		if len(r.Principals) == 0 {
			r.Principals = []string{u.Username}
		}

		pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(r.PublicKey))
		if err != nil {
			return fmt.Errorf("could not parse public key in authorized_keys format: %w", err)
		}

		lifetime := time.Duration(r.Lifetime)
		if lifetime == 0 {
			lifetime = defaultLifetime
		}
		expiry := time.Now().Add(lifetime).Truncate(time.Second)

		for _, t := range r.Principals {
			if !policy.ForUser(u).CanIssueFor(t, time.Duration(r.Lifetime)) {
				return fmt.Errorf("policy does not allow %q to issue for %q with lifetime %v", args[0], t, time.Duration(r.Lifetime))
			}
		}

		keyFn := viper.GetString("signing_key_filename")
		if keyFn == "" {
			keyFn = path.Join(viper.GetString("signing_ca_directory"), "current")
		}
		priv, err := loadSigningKey(keyFn)
		if err != nil {
			return fmt.Errorf("could not load signing key file %q: %w", signingKeyFile, err)
		}
		auth, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			return fmt.Errorf("could not create SSH signer from key: %w", err)
		}

		cert := ssh.Certificate{
			Key:             pubkey,
			Serial:          0,
			CertType:        ssh.UserCert,
			KeyId:           fmt.Sprintf("%s@%s", u.Username, h),
			ValidPrincipals: r.Principals,
			ValidAfter:      uint64(time.Now().Add(-backdate).Unix()),
			ValidBefore:     uint64(expiry.Unix()),
			Permissions: ssh.Permissions{
				Extensions: defaultExtensions,
			},
		}
		if err := cert.SignCert(rand.Reader, auth); err != nil {
			return fmt.Errorf("could not sign certificate: %w", err)
		}

		l, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_NOTICE, path.Base(os.Args[0]))
		if err != nil {
			return fmt.Errorf("could not connect to syslog for audit logging: %w", err)
		}
		var audit bytes.Buffer
		fmt.Fprintf(&audit, "Issued certificate for %s", u.Username)
		if caller != "" {
			fmt.Fprintf(&audit, " (authenticated by %s)", caller)
		}
		fmt.Fprintf(&audit, ": principals %v, valid until %s", r.Principals, expiry.Format(timeFormat))
		if _, err := audit.WriteTo(l); err != nil {
			return fmt.Errorf("could not write audit entry to syslog: %w", err)
		}

		resp := &Response{Certificate: strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(&cert)), "\n")}
		if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
			return fmt.Errorf("could not marshal response: %w", err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}
