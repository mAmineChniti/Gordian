# Gordian API Documentation

This is the API documentation for the Gordian API. The API is a RESTful API that allows you to interact with the Gordian server. The API is used to create, read, update, and delete user data from the server.

## Base URL

https://gordian.onrender.com/api/v1

## Authentication

Protected routes require a valid JWT token in the Authorization header as a Bearer token.

### Example Authorization Header

`Authorization: Bearer <your_jwt_token>`

## Endpoints

**POST** `/register` - Register a new user
Registers a new user in the system and returns a JWT token.

**Request Body:**

```json
{
  "username": "user123",
  "email": "user@example.com",
  "password": "securePassword",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Response:**

```json
{
  "message": "Registration successful",
  "user": {
    "id": "643f1c77d4fdd441ed3f2991",
    "username": "user123",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "date_joined": "2023-09-29T12:34:56Z"
  },
  "tokens": {
    "access_token": "<access_token>",
    "access_created_at": "2023-09-29T12:34:56Z",
    "expires_at": "2023-09-29T12:34:56Z",
    "refresh_token": "<refresh_token>",
    "refresh_created_at": "2023-09-29T12:34:56Z",
    "refresh_expires_at": "2023-09-29T12:34:56Z"
  }
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
Logs in a user and returns a JWT token.

**Request Body:**

```json
{
  "username": "john_doe",
  "password": "password123"
}
```

**Response:**

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

**PATCH** `/update` - Partially Update user details

**PUT** `/update` - Fully Update user details

Updates a user's details and returns the new user info.

**Request Body:**

```json
{
  "username": "john_doe_full",
  "email": "john.doe.full@example.com",
  "password": "new_password",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Response:**

```json
{
  "message": "User updated successfully",
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
Deletes a user from the system returns a simple confirmation message.

**Request:**

***Authorization Header:***
`Authorization: Bearer <your_access_token_here>`

**Response:**

```json
{
  "message": "User deleted successfully"
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
Refreshes an access token and returns a new access token.

**Request:**

***Authorization Header:***
`Authorization: Bearer <your_refresh_token_here>`

**Response:**

```json
{
  "message": "Token refreshed successfully",
  "tokens": {
    "access_token": "<new_access_token>",
    "access_created_at": "2023-10-22T14:48:00Z",
    "expires_at": "2023-10-22T15:48:00Z",
    "refresh_token": "<new_refresh_token>",
    "refresh_created_at": "2023-10-22T14:48:00Z",
    "refresh_expires_at": "2023-10-29T14:48:00Z"
}
```

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
