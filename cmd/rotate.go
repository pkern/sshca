package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var rotateCmd = &cobra.Command{
	Use:          "rotate",
	Short:        "Rotate the CA keys",
	Long:         `Creates a new CA key, makes the next key current, and rotates the current key into the past.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Generate a base set of keys.
		previous, err := getVersionOrGenerate("previous")
		if err != nil {
			return err
		}
		current, err := getVersionOrGenerate("current")
		if err != nil {
			return err
		}
		next, err := getVersionOrGenerate("next")
		if err != nil {
			return err
		}
		fmt.Printf("Current: previous: %d; current: %d; next: %d\n", previous, current, next)
		fmt.Println("Rotating keys...")
		v, err := getNextVersion(caDir)
		if err != nil {
			return fmt.Errorf("could not get next version: %w", err)
		}
		if err := generateKey(path.Join(caDir, strconv.Itoa(v))); err != nil {
			return fmt.Errorf("could not generate next key: %w", err)
		}
		if err := setStageVersion("next", v); err != nil {
			return err
		}
		if err := setStageVersion("current", next); err != nil {
			return err
		}
		if err := setStageVersion("previous", current); err != nil {
			return err
		}
		fmt.Printf("Current: previous: %d; current: %d; next: %d\n", current, next, v)
		return nil
	},
}

func resolveStageVersion(fn string) (int, error) {
	t, err := os.Readlink(fn)
	if err != nil {
		return -1, fmt.Errorf("could not resolve symlink %q: %w", fn, err)
	}
	i, err := strconv.Atoi(t)
	if err != nil {
		return -1, fmt.Errorf("could not parse symlink target %q to int: %w", t, err)
	}
	return i, nil
}

func getNextVersion(dir string) (int, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return -1, fmt.Errorf("could not read directory %q: %w", dir, err)
	}
	var versions []int
	for _, file := range files {
		v, err := strconv.Atoi(file.Name())
		if err != nil {
			continue
		}
		versions = append(versions, v)
	}
	if len(versions) == 0 {
		return 1, nil
	}
	return slices.Max(versions) + 1, nil
}

func generateKey(fn string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("could not generate ED25519 key: %w", err)
	}
	b, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return fmt.Errorf("could not marshal SSH private key: %w", err)
	}
	if err := os.WriteFile(fn, pem.EncodeToMemory(b), 0o400); err != nil {
		return fmt.Errorf("could not write private key file %q: %w", fn, err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("could not create SSH public key: %w", err)
	}
	if err := os.WriteFile(fn+".pub", ssh.MarshalAuthorizedKey(sshPub), 0o444); err != nil {
		return fmt.Errorf("could not write public key file %q: %w", fn+".pub", err)
	}
	return nil
}

func symlink(oldname string, newname string) error {
	if err := os.Symlink(oldname, newname+".new"); err != nil {
		return err
	}
	return os.Rename(newname+".new", newname)
}

func setStageVersion(stage string, version int) error {
	if err := symlink(strconv.Itoa(version), path.Join(caDir, stage)); err != nil {
		return err
	}
	return symlink(strconv.Itoa(version)+".pub", path.Join(caDir, stage+".pub"))
}

func getVersionOrGenerate(stage string) (int, error) {
	v, err := resolveStageVersion(path.Join(caDir, stage))
	if err == nil {
		return v, nil
	} else if errors.Is(err, fs.ErrNotExist) {
		v, err = getNextVersion(caDir)
		if err != nil {
			return -1, fmt.Errorf("could not get next version for %q: %w", caDir, err)
		}
		if err := generateKey(path.Join(caDir, strconv.Itoa(v))); err != nil {
			return -1, fmt.Errorf("could not generate key version %d: %w", v, err)
		}
		if err := setStageVersion(stage, v); err != nil {
			return -1, fmt.Errorf("could not set version of stage %q to %d: %w", stage, v, err)
		}
		return v, nil
	}
	return -1, err
}

func init() {
	rootCmd.AddCommand(rotateCmd)
}
