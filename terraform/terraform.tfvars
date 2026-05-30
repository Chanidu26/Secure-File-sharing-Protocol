
region     = "us-east-1"
app_name   = "securetransfer"

cognito_domain_prefix = "securetransfer-protocol-chanidu-2026"

callback_urls = [
  "http://localhost:5000/callback",
]

logout_urls = [
  "http://localhost:5000",
]

# Set to true to enable optional TOTP MFA for users
mfa_enabled = false

tags = {
  Project   = "SecureTransfer"
  ManagedBy = "Terraform"
}
