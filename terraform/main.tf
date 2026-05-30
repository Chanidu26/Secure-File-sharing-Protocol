# ── User Pool ──────────────────────────────────────────────────────────────────

resource "aws_cognito_user_pool" "main" {
  name = "${var.app_name}-user-pool"

  # Users sign in with email; preferred_username is the friendly display name
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  verification_message_template {
    default_email_option = "CONFIRM_WITH_CODE"
    email_subject        = "Your ${var.app_name} verification code"
    email_message        = "Your verification code is {####}"
  }

  password_policy {
    minimum_length                   = 8
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = false
    temporary_password_validity_days = 7
  }

  mfa_configuration = var.mfa_enabled ? "OPTIONAL" : "OFF"

  dynamic "software_token_mfa_configuration" {
    for_each = var.mfa_enabled ? [1] : []
    content { enabled = true }
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  # ── User attributes ──────────────────────────────────────────────────────────
  # email — required for sign-in
  schema {
    name                = "email"
    attribute_data_type = "String"
    required            = true
    mutable             = true
    string_attribute_constraints {
      min_length = 5
      max_length = 254
    }
  }

  schema {
    name                = "preferred_username"
    attribute_data_type = "String"
    required            = true 
    mutable             = false     
    string_attribute_constraints {
      min_length = 3
      max_length = 30
    }
  }

  admin_create_user_config {
    allow_admin_create_user_only = false  # allow self sign-up
  }

  tags = var.tags
}

# ── User Pool Domain ───────────────────────────────────────────────────────────

resource "aws_cognito_user_pool_domain" "main" {
  domain       = var.cognito_domain_prefix
  user_pool_id = aws_cognito_user_pool.main.id
}

# ── App Client ─────────────────────────────────────────────────────────────────

resource "aws_cognito_user_pool_client" "app" {
  name         = "${var.app_name}-app-client"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret = false   # public client

  access_token_validity  = 1    # hours
  id_token_validity      = 1    # hours
  refresh_token_validity = 30   # days

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  # openid + email + profile ensures preferred_username is in the ID token
  allowed_oauth_scopes                 = ["openid", "email", "profile"]

  callback_urls = var.callback_urls
  logout_urls   = var.logout_urls

  supported_identity_providers = ["COGNITO"]

  prevent_user_existence_errors = "ENABLED"
  enable_token_revocation       = true

  # Required for SRP + refresh token flows
  explicit_auth_flows = [
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]

  read_attributes  = ["email", "preferred_username", "sub"]
  write_attributes = ["email", "preferred_username"]
}
