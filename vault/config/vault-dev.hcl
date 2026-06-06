# Vault Dev Mode Configuration
# NOT for production — dev mode stores data in-memory only

ui = true

storage "inmem" {}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

# Enable Kubernetes auth method at startup
# vault auth enable kubernetes (run after startup)

log_level = "info"
log_format = "json"

# API address
api_addr = "http://0.0.0.0:8200"

# Dev root token (override with VAULT_DEV_ROOT_TOKEN_ID env var)
# Default: "root"
