# config — keys an operator generates, and nothing that is tracked

`authz-admin relay-keygen` writes a service key pair here:

| File | Mode | What it is |
|---|---|---|
| `aivan-authz.key` | `0600` | the private half. Signs `POST /devices` and `DELETE /devices/{id}` to `aivan-approval` |
| `aivan-authz.pub` | `0644` | the public half. Registered with the relay, printed by the command, and not a secret |

`.gitignore` ignores everything in this directory except this file. A key here
is a credential: whoever holds the private half can register a device key
against any user id the relay will accept, and the relay has no second opinion
about whether that device should exist.

## The lifetime of the key

1. `authz-admin relay-keygen` creates the pair and prints the public key and its
   SHA-256 fingerprint.
2. The public key is registered with the relay, on a host that can reach its
   database:

   ```console
   $ rake "service:register[aivan-authz]" KEY=aivan-authz.pub ALG=ed25519
   ```

   The fingerprint that command prints is the one the keygen printed. If the two
   disagree, one of them is a different key.
3. The private half is copied to where a secret belongs — a Kubernetes Secret, a
   `pass` entry, an offline backup — and the copy in this directory is deleted.
   A file here is convenient for the next command and a liability after it.
4. Rotation is a new name and a retired row at the relay, not a replacement: a
   signature made before retirement can still be explained.

## Why the private half never reaches the cluster

The gate's image carries one binary that serves requests. It holds no service
key and can sign nothing with one, so a process compromised in the pod cannot
register a phone against an arbitrary person's mailbox. Registrations are made
by this tool, on a workstation, with the operator credential.
