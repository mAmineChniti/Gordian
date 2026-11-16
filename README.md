# Gordian API

Gordian is a Go REST API for account registration, email confirmation, authentication, profile management, password resets and session revocation. It stores users in MongoDB, issues HMAC-signed JWTs and uses MongoDB indexes to enforce case-insensitive username and email uniqueness.

- **Stack:** Go 1.27.4, Echo v4, MongoDB, Swagger
- **Module:** `github.com/mAmineChniti/Gordian`
- **Default port:** `10000`
- **API base path:** `/api/v1`

## Requirements

- Go 1.27.4 or newer
- MongoDB 6/7, or a MongoDB Atlas connection string
- Docker (optional)

## Quick start

### Local development

```bash
cp .env.example .env
# Edit .env and set at least JWTSECRET and APP_BASE_URL.
make run
```

The service loads `.env` automatically. If MongoDB is not running locally, set `MONGODB_URI` in `.env` to a reachable server or Atlas cluster.

Once started:

- API root: `http://localhost:10000/api/v1`
- Swagger UI: `http://localhost:10000/api/v1/docs`
- Health check: `http://localhost:10000/api/v1/health`

### Docker

The API uses an external MongoDB deployment; no database container is included.

```bash
cp .env.example .env
# Set JWTSECRET, APP_BASE_URL, CORS_ALLOWED_ORIGINS and MONGODB_URI in .env.
make docker-build
make docker-run
```

Or run Docker directly:

```bash
docker build --target prod -t gordian .
docker run --rm -p 10000:10000 --env-file .env gordian
```

`make docker-run` publishes the port from `PORT` (default `10000`). The image runs as a non-root user on a distroless base and includes the email templates. `.env` is passed at runtime and is not baked into the image.

## Configuration

Configuration is read from environment variables. Missing required values cause the process to exit at startup.

### Required variables

| Variable | Description |
| --- | --- |
| `JWTSECRET` | Secret used to sign JWTs. Use at least 32 random bytes; shorter secrets log a warning. |
| `MONGODB_URI` | MongoDB connection string, for example `mongodb://localhost:27017` or `mongodb+srv://...`. |
| `DB_CONNECTION_STRING` | Alternative to `MONGODB_URI`. A bare Atlas host is prefixed with `mongodb+srv://`. |
| `APP_BASE_URL` | Public base URL of the API, used to build email confirmation links. Must be an absolute `http(s)` URL. |
| `CORS_ALLOWED_ORIGINS` | Comma-separated browser origins allowed to call the API, for example `https://app.example.com,http://localhost:3000`. Use `*` to allow any browser origin. |

`CORS_ALLOWED_ORIGINS` entries must be bare origins: no paths, queries, fragments or embedded credentials. A single `*` allows every browser origin. Because the CORS spec forbids wildcard origins combined with credentials, `Access-Control-Allow-Credentials` is disabled automatically in that mode. Protected routes still require a bearer token. Explicit origins are recommended unless any website genuinely needs to call the API.

### Optional variables

| Variable | Default | Notes |
| --- | --- | --- |
| `PORT` | `10000` | Listening port, 1–65535. |
| `DB_NAME` | `gordian` | MongoDB database name. |
| `DB_USERNAME` | unset | Applied only when the MongoDB URI does not already contain credentials. |
| `DB_PASSWORD` | unset | Used with `DB_USERNAME`. |
| `DB_AUTH_SOURCE` | `admin` | Authentication database for `DB_USERNAME`/`DB_PASSWORD`. |
| `TRUST_PROXY` | `false` | When `true`, client IPs are read from `X-Forwarded-For`. Enable only behind a trusted reverse proxy; otherwise clients can spoof IP-based rate limits. |
| `DEBUG` | `false` | Enables debug-level Echo logging. |
| `GMAIL_USERNAME` | unset | Gmail address used to send confirmation and reset emails. |
| `GMAIL_APP_PASSWORD` | unset | Google app password. Must be set together with `GMAIL_USERNAME`. |
| `ACCESS_TOKEN_TTL` | `15m` | Access token lifetime. |
| `REFRESH_TOKEN_TTL` | `168h` (7 days) | Refresh token lifetime; must be longer than `ACCESS_TOKEN_TTL`. |
| `EMAIL_CONFIRMATION_TOKEN_TTL` | `48h` | Email confirmation link lifetime. |
| `PASSWORD_RESET_TOKEN_TTL` | `1h` | Password reset token lifetime. |
| `BCRYPT_COST` | `12` | bcrypt cost, 10–14. |
| `MAX_BODY_MB` | `8` | Maximum request body size, 1–32 MB. |
| `MAX_PROFILE_PICTURE_MB` | `5` | Maximum decoded profile-picture size, 1–10 MB. `MAX_BODY_MB` must be large enough to hold the base64-encoded image. |
| `APP_TEMPLATES_DIR` | auto-detected | Optional directory containing `confirmation_page.html`, `confirmation_email.html` and `password_reset.html`. |

If `GMAIL_USERNAME` and `GMAIL_APP_PASSWORD` are both unset, email delivery is disabled and a startup warning is logged. Registration and password reset initiation still accept requests, but no email is sent. Setting only one of the two variables is a configuration error.

`MONGODB_URI` takes precedence over `DB_CONNECTION_STRING`. `DB_USERNAME`/`DB_PASSWORD` are not applied when the URI already includes credentials.

## API

All routes below are relative to `${APP_BASE_URL}/api/v1`. Interactive documentation is available at `/api/v1/docs`; the regenerated OpenAPI files live in `docs/`.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `/` (outside `/api/v1`) | No | Redirects to `/api/v1/docs`. |
| `GET` | `/api/v1` | No | Returns API banner, documentation and health paths. |
| `GET` | `/health` | No | MongoDB-backed health check. |
| `POST` | `/register` | No | Create an account and send a confirmation email. |
| `GET` | `/confirm-email/{token}` | No | Confirm an email address and render an HTML result page. |
| `POST` | `/resend-confirmation-email` | No | Request another confirmation email by address. |
| `POST` | `/login` | No | Authenticate and receive a token pair. |
| `GET` | `/refresh` | Refresh token | Exchange a refresh token for a new token pair. |
| `POST` | `/logout` | Access token | Revoke all active tokens for the current user. |
| `POST` | `/password-reset/initiate` | No | Send a password-reset email. |
| `POST` | `/password-reset/confirm` | No | Set a new password with a reset token. |
| `GET` | `/fetchuser` | Access token | Return the authenticated user's profile. |
| `POST` | `/fetchuserbyid` | Access token | Return another user's limited public profile. |
| `PUT`, `PATCH` | `/update` | Access token | Update the authenticated user's profile. |
| `DELETE` | `/delete` | Access token | Permanently delete the authenticated account. |
| `GET` | `/resend-confirmation-email` | Access token | Resend confirmation for the authenticated user. |
| `GET` | `/docs` | No | Redirect to Swagger UI. |
| `GET` | `/docs/*` | No | Swagger UI assets. |

### Authentication

Protected routes require an access token in the `Authorization` header:

```http
Authorization: Bearer <access_token>
```

Access tokens expire after `ACCESS_TOKEN_TTL` (15 minutes by default) and refresh tokens after `REFRESH_TOKEN_TTL` (7 days by default). Both are HS256 JWTs with issuer `gordian`, audience `gordian-api`, a token type (`access` or `refresh`) and a token version.

Every protected request checks the user's current token version. Changing or resetting a password, logging out, or deleting the account invalidates previously issued tokens immediately, regardless of their `exp` value. `GET /refresh` requires a refresh token and rejects deleted users and accounts whose email is no longer confirmed.

### Response format

Successful responses are JSON objects containing a `message` and, where applicable, a `user` and/or `tokens` object. Validation errors return HTTP 400 with a field-keyed map using the same names as the JSON request fields:

```json
{
  "message": "Validation failed",
  "errors": {
    "email": "invalid email format",
    "password": "password must be 8-72 characters and include uppercase, lowercase, a number and a special character"
  }
}
```

Other failures use a single message:

```json
{
  "message": "Invalid username/email or password"
}
```

Rate-limited responses return HTTP 429 with a `Retry-After` header in seconds. Common status codes:

| Status | Meaning |
| --- | --- |
| `400` | Malformed JSON, validation failure, invalid token format or missing update fields. |
| `401` | Missing/invalid/expired credentials, revoked session or incorrect current password. |
| `403` | Email address has not been confirmed. |
| `404` | Requested user or endpoint not found. |
| `409` | Username/email already registered or email already confirmed. |
| `429` | Rate limit exceeded. |
| `500` | Unexpected server, database or email-delivery failure. |
| `503` | Health check failed or authentication temporarily unavailable. |

### Registration

`POST /register`

```json
{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "P@ssw0rd!",
  "first_name": "John",
  "last_name": "Doe",
  "birthdate": "1990-01-01T00:00:00Z",
  "accept_terms": true,
  "profile_picture": "data:image/png;base64,iVBORw0KGgo..."
}
```

Rules:

- `username`: 5–20 characters, starts with a letter or digit, then letters, digits, `.`, `_` or `-`. Uniqueness is case-insensitive.
- `email`: valid address, at most 254 characters. Stored normalized to lowercase and unique case-insensitively.
- `password`: 8–72 bytes, including uppercase, lowercase, digit and special character.
- `first_name`, `last_name`: 2–50 characters.
- `birthdate`: RFC3339 timestamp; the user must be between 18 and 120 years old.
- `accept_terms`: must be `true`.
- `profile_picture`: optional. Accepts a base64 data URL for PNG, JPEG, WebP or GIF, or raw base64. The decoded image must fit `MAX_PROFILE_PICTURE_MB` and the whole request must fit `MAX_BODY_MB`.

A successful registration returns **HTTP 201**:

```json
{
  "message": "Registration successful. Please check your email to confirm your account."
}
```

If the account is created but the confirmation email cannot be sent, the response is still HTTP 201 with a message asking the client to use the resend endpoint. A duplicate username or email returns HTTP 409.

Unconfirmed accounts are not allowed to log in. Accounts that remain unconfirmed for more than three days are deleted by a periodic cleanup job.

### Email confirmation

`GET /confirm-email/{token}` renders an HTML page rather than JSON. Confirmation tokens are single-use, expire after `EMAIL_CONFIRMATION_TOKEN_TTL`, and are stored as SHA-256 hashes. Clicking an already-used or expired link returns an explanatory HTML page.

Confirmation emails can be resent at most three times per account, with a five-minute cooldown between requests. The public `POST /resend-confirmation-email` endpoint always returns the same HTTP 200 response, whether or not an unconfirmed account exists:

```json
{
  "email": "john@example.com"
}
```

The authenticated `GET /resend-confirmation-email` variant returns more specific errors (`409` if already confirmed, `429` during the cooldown or after the attempt limit).

### Login

`POST /login`

```json
{
  "identifier": "johndoe",
  "password": "P@ssw0rd!"
}
```

`identifier` accepts either the username or the email address. Invalid usernames/emails and incorrect passwords both return the same HTTP 401 response to avoid account enumeration:

```json
{
  "message": "Invalid username/email or password"
}
```

An unconfirmed account returns HTTP 403. A successful login returns the user plus a token pair:

```json
{
  "message": "Login successful",
  "user": {
    "id": "615f2e0a6c6d5c0e1a1e4a01",
    "username": "johndoe",
    "email": "john@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "birthdate": "1990-01-01T00:00:00Z",
    "profile_picture": "data:image/png;base64,...",
    "email_confirmed": true,
    "accept_terms": true,
    "date_joined": "2026-01-01T12:00:00Z"
  },
  "tokens": {
    "access_token": "<access_token>",
    "access_created_at": "2026-01-01T12:00:00Z",
    "access_expires_at": "2026-01-01T12:15:00Z",
    "refresh_token": "<refresh_token>",
    "refresh_created_at": "2026-01-01T12:00:00Z",
    "refresh_expires_at": "2026-01-08T12:00:00Z"
  }
}
```

### Refresh and logout

`GET /refresh` requires the refresh token as a Bearer token and returns a new token pair. Deleted users, revoked sessions and unconfirmed addresses are rejected.

`POST /logout` requires an access token, increments the user's token version and immediately revokes all access and refresh tokens for that account.

### Profile endpoints

`GET /fetchuser` returns the authenticated user's profile. The response contains `username`, `first_name`, `last_name`, `birthdate`, `date_joined`, `profile_picture` and `email_confirmed`; the email address and password hash are never included.

`POST /fetchuserbyid` takes a user ID and returns a limited public profile:

```json
{
  "user_id": "615f2e0a6c6d5c0e1a1e4a01"
}
```

```json
{
  "message": "User fetched successfully",
  "user": {
    "username": "johndoe",
    "first_name": "John",
    "last_name": "Doe",
    "date_joined": "2026-01-01T12:00:00Z"
  }
}
```

Birthdate, email address and confirmation state are not exposed by this endpoint.

`PUT /update` and `PATCH /update` accept any subset of `username`, `email`, `first_name`, `last_name`, `birthdate`, `profile_picture`, `password` and `current_password`.

- At least one update field is required.
- Changing the email address or password requires `current_password`.
- Changing the email address sets `email_confirmed` to `false`, sends a confirmation link to the new address and a notice to the old address. The new address must be confirmed before login or refresh succeeds.
- Changing the password revokes existing sessions and returns a fresh token pair in the `tokens` field.
- Username and email conflicts return HTTP 409; an incorrect `current_password` returns HTTP 401.
- If a profile update succeeds but its confirmation email fails, the endpoint still returns HTTP 200 with a warning message.

`DELETE /delete` permanently removes the authenticated account. A second delete of the same account returns HTTP 404 because the user no longer exists.

### Password reset

`POST /password-reset/initiate`

```json
{
  "email": "john@example.com"
}
```

The response is always the same for known and unknown addresses:

```json
{
  "message": "If an account exists with this email, a reset link will be sent"
}
```

Reset tokens are single-use, expire after `PASSWORD_RESET_TOKEN_TTL` and are stored as SHA-256 hashes. Completing a reset revokes all existing sessions.

`POST /password-reset/confirm`

```json
{
  "token": "123e4567-e89b-12d3-a456-426614174000",
  "new_password": "N3wP@ssw0rd!"
}
```

An invalid or expired token returns HTTP 400 with `Invalid or expired reset token`.

### Health

`GET /health` returns HTTP 200 when MongoDB responds:

```json
{
  "status": "ok",
  "details": {
    "message": "It's healthy"
  }
}
```

If the database cannot be reached, the endpoint returns HTTP 503.

## Rate limits and request limits

Rate limiting is in-memory and per-process. Deploy a shared limiter (for example at the reverse proxy) if you run multiple replicas.

| Action | Limit |
| --- | --- |
| Login failures | 5 per 10 minutes per IP + identifier; block 15 minutes |
| Login failures per IP | 20 per 10 minutes; block 15 minutes |
| Registration | 5 per hour per IP |
| Password reset initiation | 3 per 15 minutes per IP + email and 10 per 15 minutes per IP; block 30 minutes |
| Confirmation resend | 3 per hour per IP + email and 10 per hour per IP |
| User lookups (`/fetchuserbyid`) | 120 per minute per authenticated user |

Additional protections:

- Request bodies are capped by `MAX_BODY_MB` (8 MB default), including profile pictures.
- Decoded profile pictures are capped by `MAX_PROFILE_PICTURE_MB` (5 MB default).
- Security headers include HSTS, `X-Content-Type-Options`, `X-Frame-Options`, XSS protection and `Referrer-Policy`.
- CORS is restricted to `CORS_ALLOWED_ORIGINS`. Setting it to `*` allows any browser origin but never bypasses authentication or rate limits; CORS does not restrict non-browser clients.
- Access logs record method, route, status, latency, IP and request ID; request bodies and tokens are never logged.
- Password hashes use bcrypt at the configured cost. Email and password-reset tokens are stored hashed, not in plaintext.
- Username and email uniqueness is case-insensitive and enforced by MongoDB indexes created at startup.

When running behind a reverse proxy, terminate TLS there and set `TRUST_PROXY=true` only if the proxy strips client-supplied `X-Forwarded-For` headers. Otherwise leave it `false`.

## Development

### Commands

```bash
make build      # static Linux binary at ./main
make run        # run the API
make test       # go test -race ./...
make itest      # MongoDB integration tests (requires MONGODB_URI)
make vet        # go vet ./...
make fmt        # fail if files need gofmt
make vuln       # govulncheck with a small allowlist
make swagger    # regenerate docs/ with swag
make docker-build # build the production image
make docker-run   # run it with .env
```

The integration test creates a unique disposable database and drops it afterwards. It is skipped unless `MONGODB_URI` is set:

```bash
MONGODB_URI=mongodb://localhost:27017 make itest
```

### Project layout

| Path | Contents |
| --- | --- |
| `cmd/api` | Entry point, startup, cleanup job and graceful shutdown. |
| `internal/config` | Environment loading and validation. |
| `internal/data` | Request/response models, JWT claims and validation. |
| `internal/database` | MongoDB persistence, authentication, tokens, email flows and indexes. |
| `internal/server` | Echo routes, middleware, handlers and in-memory rate limiting. |
| `internal/services` | Gmail SMTP email delivery. |
| `internal/templates` | HTML email and confirmation-page templates. |
| `docs` | Generated Swagger/OpenAPI artifacts. |

### Vulnerability scanning

`make vuln` runs `govulncheck` and fails on any advisory outside a documented allowlist. The allowlist currently covers Echo advisories that have no fixed release; see `scripts/govulncheck.sh` and re-evaluate the list when Echo publishes patches.

## CI

- **Build workflow:** formatting, `go vet`, race-enabled unit tests, MongoDB integration tests, vulnerability scan, production build and a live health-check smoke test.
- **Lint workflow:** gofmt enforcement, `go vet` and `golangci-lint`.
- **Dependabot:** weekly update checks for Go modules, GitHub Actions and Docker base images.
- Both workflows pin Go 1.27.4.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
