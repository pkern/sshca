# sshca

A simple SSH Certificate Authority that can be run from an SSH `ForceCommand` -
to derive a short lived certificate from a touch-based authentication.

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
