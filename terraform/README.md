# Cognito Terraform Setup

Creates the AWS Cognito User Pool for SecureTransfer in ~2 minutes.

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.3
- AWS CLI configured (`aws configure`) with an IAM user that has Cognito permissions

## Steps

### 1. Edit terraform.tfvars

```hcl
cognito_domain_prefix = "securetransfer-yourname-2024"  # must be globally unique
```

### 2. Deploy

```bash
terraform init
terraform apply
```

Type `yes` when prompted. Takes about 60 seconds.

### 3. Copy the .env output

After apply completes, Terraform prints a `dot_env_block` output:

```
dot_env_block = <<EOT

  COGNITO_REGION=us-east-1
  COGNITO_USER_POOL_ID=us-east-1_AbCdEfGhI
  COGNITO_CLIENT_ID=1abc2defghij3klmnopqrstuv
  COGNITO_CLIENT_SECRET=
  COGNITO_DOMAIN=securetransfer-yourname-2024.auth.us-east-1.amazoncognito.com
  APP_BASE_URL=http://localhost:5000
  FLASK_SECRET=replace_with_random_secret

EOT
```

Paste that into your `.env` file inside the `secure-transfer-cognito/` folder.
Replace `FLASK_SECRET` with a random value:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 4. Run the app

```bash
cd ../secure-transfer-cognito
python start.py
```

Open `http://localhost:5000` — you'll see the Cognito sign-in page.

---

## Re-run outputs anytime

```bash
terraform output dot_env_block
terraform output hosted_ui_url   # direct link to test the login page
```

## Destroy

```bash
terraform destroy
```

---

## What gets created

| Resource | Name |
|----------|------|
| `aws_cognito_user_pool` | `securetransfer-user-pool` |
| `aws_cognito_user_pool_domain` | your prefix |
| `aws_cognito_user_pool_client` | `securetransfer-app-client` |

**Cost:** Cognito is free for the first 50,000 monthly active users.
