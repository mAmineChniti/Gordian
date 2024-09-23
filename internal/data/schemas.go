package data

import (
	"github.com/google/uuid"
	"time"
)

type User struct {
	ID         uuid.UUID `json:"id"`
	Username   string    `json:"username"`
	Email      string    `json:"email"`
	Password   password  `json:"password"`
	FirstName  string    `json:"first_name"`
	LastName   string    `json:"last_name"`
	DateJoined time.Time `json:"date_joined"`
}

type password struct {
	plaintext *string
	hash      string
}
