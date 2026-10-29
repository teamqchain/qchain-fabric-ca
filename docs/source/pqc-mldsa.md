# ML-DSA-44 (post-quantum) CA and client

This build of Fabric CA can run a CA whose root key and certificate are
ML-DSA-44 (FIPS 204) and enroll identities with ML-DSA-44 keys. The keys
are held by the post-quantum (PQC) BCCSP of the fabric-lib-go fork this
branch uses. This page lists what to configure, what is supported, and the
errors you get otherwise.

Nothing changes for a classical CA: `fabric-ca-server init` and
`fabric-ca-client` still generate the same default configuration files
(ECDSA P-256 keys, `bccsp.default: SW`), and a classical CA behaves as
before.

## Build

ML-DSA support needs a build with the `pqc` tag, for both binaries:

```
go build -tags pqc -o <dir>/fabric-ca-server ./cmd/fabric-ca-server
go build -tags pqc -o <dir>/fabric-ca-client ./cmd/fabric-ca-client
```

`pkcs11 pqc` works as well. The `make` targets build with `-tags pkcs11`
only, so they do not include ML-DSA support. A `pqc` build needs cgo and
liboqs (through liboqs-go), which the PQC BCCSP links for ML-KEM.

Without the `pqc` tag, PQC settings fail with these errors:

- a server or client with `bccsp.default: PQC` fails to initialize its
  BCCSP: `PQC BCCSP requires building with the pqc tag`;
- a key request with `algo: mldsa44` fails: `key algorithm mldsa44
  requires a build with -tags pqc`;
- importing an ML-DSA private key file fails: `ML-DSA private keys need the
  PQC BCCSP: build with -tags pqc and set bccsp.default to PQC`.

None of these fall back to ECDSA.

## Configuration

Start from the configuration file that `fabric-ca-server init` or the
client generates and change the following settings, or use the complete
examples below.

### `bccsp`

```yaml
bccsp:
  default: PQC
  pqc:
    keystorepath: msp/keystore
```

- Write `PQC` in upper case. The BCCSP factory only knows `PQC`; `pqc`
  fails with `Could not find BCCSP, no 'pqc' provider`.
- `pqc.keystorepath` is optional.
  - **Server:** a configured path is used; a relative path is relative to
    the server's home directory. The default is `msp/keystore`.
  - **Client:** as with the `SW` BCCSP, the keystore is always
    `<mspdir>/keystore` under the client's home directory, and
    `keystorepath` is ignored.
- The keystore stores each ML-DSA private key unencrypted as PKCS#8 in a
  file named `<ski>_sk`. A keystore password is not supported: do not set
  `bccsp.pqc.password`. A password in the YAML file currently fails while
  the configuration is decoded, with a `cannot parse 'bccsp.PQC.Password[0]'`
  error. A password that reaches the BCCSP configuration in any other way
  fails with `bccsp.pqc.password is not supported: the PQC BCCSP stores
  ML-DSA private keys unencrypted; remove the password`.

### `csr.keyrequest`

```yaml
csr:
  keyrequest:
    algo: mldsa44
```

- `mldsa44` is the only ML-DSA parameter set. `mldsa65` and `mldsa87` are
  rejected (`Invalid algorithm: ...`), and an ML-DSA-65 or ML-DSA-87 key
  file is rejected on import.
- Omit `size` or set it to 0. The generated files contain `size: 256`,
  which fails with `Invalid mldsa44 key size: 256 (omit the size or set it
  to 0)`.
- The generated files also contain `algo: ecdsa`. With `bccsp.default:
  PQC` that fails with `unsupported PQC key-generation algorithm
  "ECDSAP256"`, so `algo` must be changed to `mldsa44`. When a client or
  server configuration has no key request at all, `bccsp.default: PQC`
  selects `mldsa44`.

### Server TLS

A CA with `bccsp.default: PQC` does not generate its own TLS certificate.
With TLS enabled, `tls.certfile` and `tls.keyfile` must both point to an
external ECDSA certificate and key, for example from a TLS CA. Otherwise
the server refuses to start, before it writes anything, with:

```
TLS without tls.keyfile is not supported when bccsp.default is PQC: set tls.certfile and tls.keyfile to an external ECDSA certificate and key
```

TLS itself stays ECDSA; clients list the TLS CA certificate in
`tls.certfiles` as usual. A PQC CA with TLS disabled also starts.

### CA certificate and key

- **New CA:** without `ca.certfile` and `ca.keyfile` files, the CA creates
  a self-signed ML-DSA-44 root (`ca-cert.pem`) and keeps its key in the
  PQC keystore.
- **Existing CA certificate and key**, for example from cryptogen: set
  `ca.certfile` to the ML-DSA-44 CA certificate and `ca.keyfile` to its
  PKCS#8 private key (cryptogen's `priv_sk`).
  - On start, the key is imported into the keystore as `<ski>_sk`, and
    the CA issues certificates under that certificate.
  - A key file that does not match the certificate is refused at start:
    `Public key and private key do not match`.

### Key families

- A CA with an ML-DSA certificate only signs ML-DSA certificate requests.
- A CA with a classical certificate only signs classical requests.
- A request from the other family is refused with `CSR public key
  algorithm <alg> does not match the CA certificate's <alg> key: a CA only
  signs requests with the same key family (ML-DSA vs classical)`.

## Identities and requests

- **Token-authenticated requests:** ML-DSA identities can make every
  request that needs a token, such as register, reenroll, revoke and
  gencrl. The CA signs CRLs with its ML-DSA-44 key.
- **Token format:** an ML-DSA token has the same format as an ECDSA
  token, a signature over the SHA-256 digest of the request.
- **Unsupported identity keys:** identities with RSA or Ed25519 keys get
  `token authentication is not supported for <alg> keys` from the client.

## Not covered

- Intermediate CAs with ML-DSA keys have not been tested.
- Idemix is unchanged.

## Example server configuration

`fabric-ca-server-config.yaml` in the server's home directory. Settings not
listed keep their defaults. `tls/tls-cert.pem` and `tls/tls-key.pem` are an
ECDSA TLS certificate and key from your TLS CA.

```yaml
port: 7054

tls:
  enabled: true
  certfile: tls/tls-cert.pem
  keyfile: tls/tls-key.pem

ca:
  name: pqc-ca

registry:
  maxenrollments: -1
  identities:
     - name: admin
       pass: adminpw
       type: client
       affiliation: ""
       attrs:
          hf.Registrar.Roles: "*"
          hf.Registrar.DelegateRoles: "*"
          hf.Revoker: true
          hf.IntermediateCA: true
          hf.GenCRL: true
          hf.Registrar.Attributes: "*"
          hf.AffiliationMgr: true

csr:
  cn: pqc-ca
  keyrequest:
    algo: mldsa44

bccsp:
  default: PQC
  pqc:
    keystorepath: msp/keystore
```

Start it with `fabric-ca-server start`. As for any CA, the bootstrap
identity comes from `registry.identities` when the configuration file
exists; the `-b` option only fills it in when the server writes a default
configuration file.

## Example client configuration

`fabric-ca-client-config.yaml` in the client's home directory.
`tls-ca-cert.pem` is the certificate of the TLS CA that issued the
server's TLS certificate.

```yaml
url: https://localhost:7054

tls:
  certfiles:
    - tls-ca-cert.pem

csr:
  keyrequest:
    algo: mldsa44

bccsp:
  default: PQC
```

Enroll, register and enroll a second identity:

```
fabric-ca-client enroll -u https://admin:adminpw@localhost:7054
fabric-ca-client register --id.name alice --id.secret alicepw --id.type client
fabric-ca-client enroll -u https://alice:alicepw@localhost:7054 -M alice-msp
```

The enrollment certificates are ML-DSA-44 and chain to the CA's ML-DSA-44
root.

<!--- Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/ -->
