# 🛡 SecureTransfer — Cognito Edition

End-to-end encrypted file sharing with **AWS Cognito** handling all authentication.

## What changed from the original

| Before | After |
|--------|-------|
| Custom username/password (no real auth) | AWS Cognito Hosted UI (email, MFA, Google SSO, etc.) |
| Flask sessions with `X-Session-Token` header | Cognito JWT Bearer tokens verified on every API call |
| Manual register/login modal in the app | Cognito's polished, production-ready Hosted UI |
| `X-Username` header trusted by server | Username extracted from verified JWT — server trusts Cognito |

Everything else is **identical**: browser-side crypto, AES-GCM encryption, RSA-OAEP key wrapping, RSA-PSS signatures, HMAC verification, zero-knowledge server.

---

## Architecture

```
         ┌──────────────────────────┐
         │      AWS Cognito         │
         │  Hosted UI + User Pool   │
         │  (email, MFA, Google…)   │
         └────────────┬─────────────┘
                      │  JWT (ID + Access tokens)
                      ▼
         ┌──────────────────────────┐
         │       Flask Server       │
         │  - /login → Cognito UI   │
         │  - /callback → tokens    │
         │  - verifies JWT on APIs  │
         │  - stores ciphertext     │
         │  - stores public keys    │
         └────────────┬─────────────┘
                      │  encrypted blobs only
                      ▼
         ┌──────────────────────────┐
         │       Browser            │
         │  - RSA key generation    │
         │  - AES-GCM encryption    │
         │  - HMAC signing          │
         │  - RSA-PSS signatures    │
         │  - File decryption       │
         └──────────────────────────┘
```

---

## Setup

### 1. Create a Cognito User Pool

1. Go to **AWS Console → Cognito → User Pools → Create user pool**
2. Choose **Email** as the sign-in option
3. Configure password policy and MFA as desired
4. Under **App integration → App clients**, create a new app client:
   - Choose **Public client** (or Confidential if you set a secret)
   - Enable **Cognito Hosted UI**
   - Add callback URL: `http://localhost:5000/callback`
   - Add sign-out URL: `http://localhost:5000`
   - Enable OAuth scopes: `openid`, `email`, `profile`
5. Under **App integration → Domain**, create a Cognito domain (e.g. `myapp.auth.us-east-1.amazoncognito.com`)

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your Cognito values
```

```env
COGNITO_REGION=us-east-1
COGNITO_USER_POOL_ID=us-east-1_XXXXXXXXX
COGNITO_CLIENT_ID=your_client_id_here
COGNITO_CLIENT_SECRET=          # leave blank if no secret
COGNITO_DOMAIN=myapp.auth.us-east-1.amazoncognito.com
APP_BASE_URL=http://localhost:5000
FLASK_SECRET=your_random_secret_here
```

### 3. Install and run

```bash
pip install -r requirements.txt
python start.py
```

Open `http://localhost:5000` in your browser.

---

## Flow

1. **User visits** `http://localhost:5000`
2. **Flask checks** session — if no token, shows **Sign in with Cognito** button
3. **User clicks** — redirected to Cognito Hosted UI (signup/login/MFA/Google)
4. **Cognito redirects** back to `/callback` with an auth code
5. **Flask exchanges** code for JWT tokens, stores in server-side session
6. **Browser fetches** `/api/me` — gets the JWT access token
7. **Browser generates** RSA-OAEP + RSA-PSS key pairs (stays in memory)
8. **Browser registers** public keys via `/api/register_keys` (JWT required)
9. **File transfer** — all subsequent API calls include `Authorization: Bearer <JWT>`
10. **Flask verifies** every JWT against Cognito's JWKS endpoint

---

## JWT Verification

`server.py` verifies tokens by:
1. Checking **issuer** matches your User Pool
2. Checking **expiry** (`exp` claim)
3. Verifying **RS256 signature** against Cognito's JWKS (requires `cryptography` library)

If the `cryptography` library is missing, signature verification is skipped (dev mode only — install it for production).

---

## API Reference

All API endpoints require `Authorization: Bearer <access_token>` header.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/register_keys` | Register/update RSA public key bundle |
| GET | `/api/users` | List other registered users |
| GET | `/api/get_public_key/<username>` | Get a user's public key bundle |
| POST | `/api/initiate_transfer` | Start a file transfer |
| POST | `/api/upload_chunk` | Upload an encrypted chunk |
| GET | `/api/inbox` | Get pending transfers for current user |
| GET | `/api/get_chunk` | Download an encrypted chunk |
| POST | `/api/complete_transfer` | Mark transfer as complete |
| GET | `/api/status` | Server statistics |
| GET | `/api/logs` | Recent server events |

### Non-auth endpoints (session-based)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/login` | Redirect to Cognito Hosted UI |
| GET | `/callback` | OAuth2 callback — exchange code for tokens |
| GET | `/logout` | Clear session + redirect to Cognito logout |
| GET | `/api/me` | Return current session tokens to browser |

---

## Security notes

- **Private keys** are generated in browser memory and never transmitted
- **Session tokens** are stored in Flask server-side session (cookie-based, HMAC-signed)
- **JWTs** are validated on every API call — no persistent session state in Flask beyond the OAuth callback
- **JWKS** are cached in memory — restart server to force refresh
- **Perfect Forward Secrecy** — re-login generates fresh keys; old transfers become unreadable
- For **production**: use HTTPS, set `SESSION_COOKIE_SECURE=True`, use Redis for sessions
