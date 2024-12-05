# sshca

A simple SSH Certificate Authority that can be run from an SSH `command=`
restriction - to derive a short lived certificate from a touch-based
authentication.

## Getting a certificate

```sh
# Install the client
$ go install github.com/pkern/sshca@latest
```

```sh
# Configure for your instance
$ cat <<EOF > ~/.sshca.toml
ca_host = 'cahost.example.com'
ca_user = 'sshca'
domain = 'example'
lifetime = '19h0m0s'
principals = ['root', '$USER']
EOF
```

```sh
# Get your key daily
$ sshca get
# Touch your key to SSH
Identity added: /run/user/1000/sshca/example (SSHCA/example authentication key (2024-11-06 20:42:57.164289438))
Certificate added: /run/user/1000/sshca/example-cert.pub (pkern@sshca-host)
$ ssh-keygen -L -f /run/user/1000/sshca/example-cert.pub
/run/user/1000/sshca/example-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        Signing CA: ED25519 SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb (using ssh-ed25519)
        Key ID: "user@cahost"
        Serial: 0
        Valid: from 2024-11-09T14:15:50 to 2024-11-10T09:20:50
        Principals:
                root
                user
        Critical Options: (none)
        Extensions:
                permit-X11-forwarding
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
                permit-user-rc
# Shell to some host that accepts the CA
```

You might want to configure SSH to try the CA's certificate first - otherwise
SSH seems to still prefer the Security Key over the certificate in most
circumstances:

```sh
$ cat >> ~/.ssh/config
Match host *.example.com
        IdentitiesOnly yes
        IdentityFile /run/user/%i/sshca/example
        IdentityFile ~/.ssh/id_ecdsa_sk
```

## Setting up the CA

You need to setup a host where users can log into (preferably) a dedicated user
via SSH. For this role account you auto-generate an `authorized_keys` file
based on the existing `sk-` keys you collected from your user base.

In the above setup, the CA runs as user `sshca` on host `cahost.example.com`.
`authorized_keys` would look like this:

```
command="/path/to/sshca run user",restrict sk-ssh-ed25519@openssh.com [...]
command="/path/to/sshca run anotheruser",restrict sk-ssh-ed25519@openssh.com [...]
```

The CA expects the location of the signing key in `~/.sshca.toml`:

```
signing_key_filename = "/home/sshca/ca/current"
```

The signing key can be generated using the usual OpenSSH tooling. You likely
want to regularly rotate the CA's key and distribute current, old, and next CA
keys to all of the hosts you want users to be able to authenticate to.  In the
above example `current` is a symlink to a versioned private key file.

The default, compiled-in policy of sshca will only allow users that are in the
Unix group `adm` on the CA's host to mint certificates for user `root`.
Everyone is restricted to just the same username the CA binary is run for -
i.e. what is passed in on the command-line.
