package api_sec

import (
	"errors"
	"time"
)

type User struct {
	ID       int
	Username string
	Password string
	Role     string
}

type Account struct {
	ID        int
	UserID    int
	Balance   float64
	CreatedAt time.Time
}

var users = make(map[int]User)
var accounts = make(map[int]Account)

var (
	ErrInvalidRole       = errors.New("role must be either 'user' or 'admin'")
	ErrWeakPassword      = errors.New("password must be at least 8 characters long and contain at least one letter")
	ErrDuplicateAdmin    = errors.New("you cannot sign up as 'admin' if you are already a 'user'")
	ErrUsernameMissing   = errors.New("username is required and must be unique")
	ErrUserNotFound      = errors.New("user not found")
	ErrAccountNotFound   = errors.New("account not found")
	ErrInsufficientFunds = errors.New("insufficient funds")
	ErrNegativeSum       = errors.New("Negative Sum is not allowd")
)
