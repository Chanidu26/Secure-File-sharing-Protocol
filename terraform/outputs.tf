output "COGNITO_REGION" {
  value = var.region
}

output "COGNITO_USER_POOL_ID" {
  description = "User Pool ID"
  value       = aws_cognito_user_pool.main.id
}

output "COGNITO_CLIENT_ID" {
  description = "App Client ID"
  value       = aws_cognito_user_pool_client.app.id
}

output "COGNITO_CLIENT_SECRET" {
  description = "Empty — public client has no secret"
  value       = ""
}

output "COGNITO_DOMAIN" {
  description = "Cognito Hosted UI domain (no https://)"
  value       = "${aws_cognito_user_pool_domain.main.domain}.auth.${var.region}.amazoncognito.com"
}

output "dot_env_block" {
  description = "Paste this entire block into your .env file"
  value       = <<-EOT

    COGNITO_REGION=${var.region}
    COGNITO_USER_POOL_ID=${aws_cognito_user_pool.main.id}
    COGNITO_CLIENT_ID=${aws_cognito_user_pool_client.app.id}
    COGNITO_CLIENT_SECRET=
    COGNITO_DOMAIN=${aws_cognito_user_pool_domain.main.domain}.auth.${var.region}.amazoncognito.com
    APP_BASE_URL=http://localhost:5000
    FLASK_SECRET=replace_with_random_secret

  EOT
}

output "hosted_ui_signup_url" {
  description = "Direct link to the sign-up page (shows email + preferred_username fields)"
  value       = "https://${aws_cognito_user_pool_domain.main.domain}.auth.${var.region}.amazoncognito.com/signup?client_id=${aws_cognito_user_pool_client.app.id}&response_type=code&scope=openid+email+profile&redirect_uri=${urlencode(var.callback_urls[0])}"
}

output "hosted_ui_login_url" {
  description = "Direct link to the login page"
  value       = "https://${aws_cognito_user_pool_domain.main.domain}.auth.${var.region}.amazoncognito.com/login?client_id=${aws_cognito_user_pool_client.app.id}&response_type=code&scope=openid+email+profile&redirect_uri=${urlencode(var.callback_urls[0])}"
}

output "jwks_url" {
  description = "JWKS endpoint Flask uses to verify JWT signatures"
  value       = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.main.id}/.well-known/jwks.json"
}
