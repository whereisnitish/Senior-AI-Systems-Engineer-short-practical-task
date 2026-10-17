# Least-privilege policy for the instagram-ops application token.
#   vault policy write instagram-ops config/vault/instagram-ops-policy.hcl
#
# Runtime secrets the application must use (mail relay, Meta read-only token, proxy credentials): read.
path "secret/data/smtp/*"    { capabilities = ["read"] }
path "secret/data/meta/*"    { capabilities = ["read"] }
path "secret/data/proxies/*" { capabilities = ["read"] }

# Instagram password, backup codes and TOTP setup key: existence and version only, never the value.
# (No rule for secret/data/instagram/*, so reading those values is denied.)
path "secret/metadata/instagram/*" { capabilities = ["read"] }
path "secret/metadata/smtp/*"      { capabilities = ["read"] }
path "secret/metadata/meta/*"      { capabilities = ["read"] }
path "secret/metadata/proxies/*"   { capabilities = ["read"] }

# No write, delete or list anywhere: humans store and rotate secrets; the application only checks them.
