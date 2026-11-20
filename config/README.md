# config — not where the service key lives

`authz-admin relay-keygen` writes the pair to the operator config directory,
which does not depend on the working directory:

| Order | Where |
|---|---|
| 1 | `--dir`, when the operator named one |
| 2 | `AIVAN_SERVICE_KEY_DIR` |
| 3 | `$XDG_CONFIG_HOME/aivan/keys`, or `~/.config/aivan/keys` |

| File | Mode | What it is |
|---|---|---|
| `aivan-authz.key` | `0600` | the private half. Signs `POST /devices` and `DELETE /devices/{id}` to `aivan-approval` |
| `aivan-authz.pub` | `0644` | the public half. Registered with the relay, printed by the command, and not a secret |

The directory is `0700`. It is not `~/.aivan`: that directory is the forge home,
and worker containers mount pieces of it. A signing key there would travel with
files that are copied and logged.

This repository directory is gitignored except for this file, so a pair left
here by an older `relay-keygen` is not committed. It is also the wrong place:
a command run from another checkout will not see it. Move an existing pair:

```console
$ mkdir -p ~/.config/aivan/keys
$ chmod 700 ~/.config/aivan/keys
$ mv config/aivan-authz.key config/aivan-authz.pub ~/.config/aivan/keys/
$ chmod 600 ~/.config/aivan/keys/aivan-authz.key
```

Generating a new pair is a different key. The relay refuses signatures from it
until that new public half is registered.

A key is a credential: whoever holds the private half can register a device key
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
