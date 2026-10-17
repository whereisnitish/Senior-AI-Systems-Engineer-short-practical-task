# Candidate-run local HashiCorp Vault for the live run (NOT the company vault).
# Start it from the project folder, in its own terminal:
#   vault server "-config=config/vault/vault-local.hcl"
# (keep the quotes: Windows PowerShell 5.1 splits an unquoted -config=...hcl argument at the dot)
#
# Loopback only, so TLS is off; never expose this listener on a network.
# Encrypted storage lives in ./vault-data (git-ignored and never packaged).
# After every restart Vault starts SEALED: run `vault operator unseal` before using the app.

storage "file" {
  path = "./vault-data"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = "true"
}

api_addr      = "http://127.0.0.1:8200"
ui            = true
disable_mlock = true # mlock is unavailable on Windows
