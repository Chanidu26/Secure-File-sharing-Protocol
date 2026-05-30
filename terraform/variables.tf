variable "region" {
  description = "AWS region to deploy Cognito in"
  type        = string
  default     = "us-east-1"
}

variable "app_name" {
  description = "Application name — used as a prefix for all resource names"
  type        = string
  default     = "securetransfer"
}

variable "cognito_domain_prefix" {
  description = <<-EOT
    Cognito Hosted UI subdomain prefix.
    Must be globally unique across all AWS accounts.
    Final URL: https://<prefix>.auth.<region>.amazoncognito.com
    Allowed characters: lowercase letters, numbers, hyphens.
  EOT
  type        = string
  # Example: "securetransfer-myname-2024"
  # Change this — it must be unique globally
}

variable "callback_urls" {
  description = "List of allowed OAuth2 callback URLs (must match exactly what your app uses)"
  type        = list(string)
  default     = [
    "http://localhost:5000/callback",
  ]
}

variable "logout_urls" {
  description = "List of allowed logout redirect URLs"
  type        = list(string)
  default     = [
    "http://localhost:5000",
  ]
}

variable "mfa_enabled" {
  description = "Enable TOTP (authenticator app) MFA as optional for users"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {
    Project     = "SecureTransfer"
    ManagedBy   = "Terraform"
  }
}
