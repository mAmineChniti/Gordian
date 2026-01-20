# Gordian API Documentation

This is the API documentation for the Gordian API. The API is a RESTful API that allows you to interact with the Gordian server. The API is used to create, read, update, and delete user data from the server.

## Base URL

https://gordian.onrender.com/api/v1

## API Documentation UI

- The interactive Swagger UI is exposed at the `/docs` route under the API base path. For example, visit `https://gordian.onrender.com/api/v1/docs` to view the API documentation and try endpoints.

## Authentication

Protected routes require a valid JWT token in the Authorization header as a Bearer token.

### Example Authorization Header

`Authorization: Bearer <your_jwt_token>`

## Endpoints


**POST** `/register` - Register a new user
Registers a new user in the system. Returns a success message or a map of validation errors.

**Request Body:**

```json
{
  "username": "user123",
  "email": "user@example.com",
  "password": "securePassword",
  "first_name": "John",
  "last_name": "Doe",
  "birthdate": "2000-01-01T00:00:00Z",
  "accept_terms": true,
  "profile_picture": "<base64 string>"
}
```

**Success Response:**

```json
{
  "message": "Registration successful"
}
```

**Validation Error Response:**

```json
{
  "errors": {
    "username": "username must be at least 5 characters",
    "email": "invalid email format",
    "password": "password must contain at least one uppercase, lowercase, number, or special character"
  }
}
```

**Conflict Response:**

```json
{
  "message": "Username or email is already registered"
}
```

**Example Usage:**

```typescript
const newUser: User = {
  username: 'john_doe',
  email: 'john.doe@example.com',
  password: 'password123',
  first_name: 'John',
  last_name: 'Doe',
};

async function register(user: User) {
  const response = await fetch(`${BASE_URL}/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(user),
  });

  if (!response.ok) {
    throw new Error('Registration failed');
  }

  const data = await response.json();
  return data;
}

register(newUser)
  .then(data => console.log(data))
  .catch(error => console.error(error));
```


**POST** `/login` - Login a user
Logs in a user and returns user info and tokens. Returns validation errors or authentication errors as appropriate.

**Request Body:**

```json
{
  "identifier": "john_doe", // username or email
  "password": "password123"
}
```

**Success Response:**

```json
{
  "message": "Login successful",
  "user": {
    "id": "615f2e0a6c6d5c0e1a1e4a01",
    "username": "john_doe",
    "email": "john.doe@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "date_joined": "2023-10-22T14:48:00Z"
  },
  "tokens": {
    "access_token": "<access_token>",
    "access_created_at": "2023-10-22T14:48:00Z",
    "access_expires_at": "2023-10-22T15:48:00Z",
    "refresh_token": "<refresh_token>",
    "refresh_created_at": "2023-10-22T14:48:00Z",
    "refresh_expires_at": "2023-10-29T14:48:00Z"
  }
}
```

**Validation Error Response:**

```json
{
  "errors": {
    "identifier": "identifier is required",
    "password": "password must contain at least one uppercase, lowercase, number, or special character"
  }
}
```

**Authentication Error Response:**

```json
{
  "message": "Username or email not found"
}
// or
{
  "message": "Incorrect password"
}
// or
{
  "message": "Email not confirmed. Please confirm your email before logging in."
}
// or
{
  "message": "Too many failed login attempts. Please try again later."
}

**Example Usage:**

```typescript
async function login(username: string, password: string) {
  const response = await fetch(`${BASE_URL}/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username, password }),
  });

  if (!response.ok) {
    throw new Error('Login failed');
  }

  const data = await response.json();
  return data;
}

login('john_doe', 'password123')
  .then(data => console.log(data))
  .catch(error => console.error(error));
```


**PATCH/PUT** `/update` - Update user details
Updates a user's details. Returns updated user info or validation errors.

**Request Body:**

```json
{
  "username": "john_doe_full",
  "email": "john.doe.full@example.com",
  "password": "new_password",
  "first_name": "John",
  "last_name": "Doe",
  "birthdate": "2000-01-01T00:00:00Z",
  "profile_picture": "<base64 string>"
}
```

**Success Response:**

```json
{
  "message": "Profile updated successfully",
  "user": {
    "id": "615f2e0a6c6d5c0e1a1e4a01",
    "username": "john_doe_full",
    "email": "john.doe.full@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "date_joined": "2023-10-22T14:48:00Z"
  }
}
```

**Validation Error Response:**

```json
{
  "errors": {
    "email": "invalid email format",
    "username": "username must be at least 5 characters"
  }
}
```

**Conflict Response:**

```json
{
  "message": "Username is already taken"
}
// or
{
  "message": "Email is already registered"
}

**Example Usage:**

```typescript
const UpdatedUser: User = {
  username: 'john_doe_full',
  email: 'john.doe.full@example.com',
  password: 'new_password',
  first_name: 'John',
  last_name: 'Doe',
};

async function updateUser(accessToken: string, user: User) {
  const response = await fetch(`${BASE_URL}/update`, {
    method: 'PUT', // or 'PATCH'
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`,
    },
    body: JSON.stringify(user),
  });

  if (!response.ok) {
    throw new Error('Update failed');
  }

  const data = await response.json();
  return data;
}

updateUser('your_access_token_here', UpdatedUser)
  .then(data => console.log(data))
  .catch(error => console.error(error));
```


**DELETE** `/delete` - Deletes a user
Deletes a user from the system. Requires authentication.

**Request:**

***Authorization Header:***
`Authorization: Bearer <your_access_token_here>`

**Success Response:**

```json
{
  "message": "Account deleted successfully"
}
```

**Example Usage:**

```typescript
async function deleteUser(accessToken: string) {
  const response = await fetch(`${BASE_URL}/delete`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    throw new Error('Delete failed');
  }

  const data = await response.json();
  return data;
}

deleteUser('your_access_token_here')
  .then(data => console.log(data))
  .catch(error => console.error(error));
```


**GET** `/refresh` - Refreshes an access token
Refreshes an access token and returns new tokens. Requires a valid refresh token.

**Request:**

***Authorization Header:***
`Authorization: Bearer <your_refresh_token_here>`

**Success Response:**

```json
{
  "message": "Tokens refreshed successfully",
  "tokens": {
    "access_token": "<new_access_token>",
    "access_created_at": "2023-10-22T14:48:00Z",
    "access_expires_at": "2023-10-22T15:48:00Z",
    "refresh_token": "<new_refresh_token>",
    "refresh_created_at": "2023-10-22T14:48:00Z",
    "refresh_expires_at": "2023-10-29T14:48:00Z"
  }
}
```

**Password Reset**

**POST** `/password-reset/initiate` - Initiate password reset

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Success Response:**
```json
{
  "message": "If an account exists with this email, a reset link will be sent"
}
```

**Validation Error Response:**
```json
{
  "errors": {
    "email": "invalid email format"
  }
}
```

**POST** `/password-reset/confirm` - Confirm password reset

**Request Body:**
```json
{
  "token": "<reset_token>",
  "new_password": "newPassword123!"
}
```

**Success Response:**
```json
{
  "message": "Password reset successfully"
}
```

**Validation Error Response:**
```json
{
  "errors": {
    "token": "invalid token format",
    "new_password": "password must contain at least one uppercase, lowercase, number, or special character"
  }
}
```

### Error Handling

All validation errors are returned as an `errors` object mapping field names to error messages. Authentication and other errors are returned as a `message` string.

### Security & Best Practices

- All sensitive endpoints are protected by JWT authentication.
- Email confirmation is required before login.
- Brute-force protection is enforced on login (rate limiting by IP and identifier).
- Passwords must meet complexity requirements.
- Email and username uniqueness is enforced on registration and update.
- All error responses are designed for easy frontend parsing.

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
