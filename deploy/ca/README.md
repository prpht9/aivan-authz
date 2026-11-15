# The house root CA, and the certificate Traefik serves

This directory holds the **public** certificate of the root CA that signs
`aivan-hud.home.arpa`. It is meant to be installed on every device that logs in.
It holds no private key, and the private key must never be added here.

## What is here

| File | What it is |
|---|---|
| `ca/pocharness-root-ca.crt` | the root certificate, public, safe to distribute |

```
subject = C=US, ST=California, L=SF, O=PocHarness, CN=PocHarness Root CA
issuer  = (self-signed, the same)
valid   = 2026-10-22 .. 2036-10-19
sha256    = 2A:B4:B3:67:6E:D0:9A:1F:32:CB:6B:70:83:38:18:5C:2B:1D:EE:FC:DF:F7:F0:1C:7F:36:3A:0C:17:27:26:2B
```

## What Traefik serves

The `aivan-hud-tls` secret in `hermes-agent` holds a leaf issued by that root:

```
subject = CN=aivan-hud.home.arpa, O=AIVAN
issuer  = CN=PocHarness Root CA
valid   = 2026-11-15 .. 2029-02-17
sha256    = CE:77:09:5C:C6:41:0D:95:18:1D:2D:2C:CB:55:3B:43:C5:72:85:93:A2:83:93:E3:FC:E0:8B:E2:3B:11:6F:FA
```

The leaf names one host in its SAN. **Adding a host means issuing a new leaf
with that name in `subjectAltName`**; existing devices trust the root, so a new
leaf needs no redistribution of the root.

`aivan-hud-tls` is referenced by all three IngressRoutes (`aivan-hud-gate`,
`aivan-hud-gated`, `aivan-hud-public`), so one secret covers the whole host.

## Installing the root on a device

| Platform | What to do |
|---|---|
| Debian/Ubuntu | `cp pocharness-root-ca.crt /usr/local/share/ca-certificates/ && update-ca-certificates` |
| macOS | import into Keychain, mark **Always Trust** |
| iOS | AirDrop or serve the file, then Settings → General → VPN & Device Management → install, then Settings → General → About → Certificate Trust Settings → enable |
| Android | Settings → Security → Encryption & credentials → Install a certificate → CA certificate |
| Firefox | Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import |

## Verifying an install

```console
$ openssl s_client -connect aivan-hud.home.arpa:443 -servername aivan-hud.home.arpa \
    -CAfile deploy/ca/pocharness-root-ca.crt </dev/null | grep "Verify return code"
Verify return code: 0 (ok)
```

## Replacing the certificate

The root's private key is **not** in this repository. It lives on `rpi4-0` at
`/etc/aivan/certs/ca-sign.pem`, which holds the certificate and its key in one
file and must be kept root-readable only. Anyone holding it can mint a
certificate for any host in the house.

To issue a replacement leaf:

```console
$ cat > leaf.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = aivan-hud.home.arpa
O  = AIVAN
[v3]
subjectAltName = DNS:aivan-hud.home.arpa
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF
$ openssl req -newkey rsa:2048 -nodes -keyout tls.key -out tls.csr -config leaf.cnf
$ openssl x509 -req -in tls.csr -CA ca-sign.pem -CAkey ca-sign.pem -CAcreateserial \
    -out tls.crt -days 825 -extfile leaf.cnf -extensions v3
$ openssl verify -CAfile deploy/ca/pocharness-root-ca.crt tls.crt
$ kubectl -n hermes-agent create secret tls aivan-hud-tls \
    --cert=tls.crt --key=tls.key --dry-run=client -o yaml | kubectl apply -f -
```

OpenSSL 3 spells the signing key `-CAkey`; the older spelling `-keyfile` is
refused.

Back up the secret before replacing it, so a bad leaf can be rolled back:

```console
$ kubectl -n hermes-agent get secret aivan-hud-tls -o yaml > aivan-hud-tls.backup.yaml
```

Traefik picks up a changed `secretName` without a restart. If it does not,
`kubectl -n kube-system rollout restart deploy/traefik` forces it.
