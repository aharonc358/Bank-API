package api_sec

import (
	"encoding/json"
	logger "f5_proj/middleware"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// SERVER START
type APIServer struct {
	listenAddr string
}

func NewAPIServer(listenAddr string) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
	}
}

// the  EndPoints of the server, according ot the role and request. The Auth function wraps all the functions so theyll be a proper Handlers functions and also pass the Claims.
func (s *APIServer) Run() {
	router := mux.NewRouter()
	router.HandleFunc("/register", Register).Methods("POST")
	router.HandleFunc("/login", Login).Methods("POST")
	router.HandleFunc("/users", Auth(UserHandler)).Methods("GET") // Admin only
	router.HandleFunc("/account", Auth(AccountsHandler)).Methods("POST", "GET")
	router.HandleFunc("/transfer", Auth(foo)).Methods("POST")
	router.HandleFunc("/balance", Auth(BalanceHandler)).Methods("GET", "POST", "DELETE")
	loggedRouter := logger.LogRequestResponse(router)
	fmt.Println("Server is starting on", s.listenAddr)
	http.ListenAndServe(s.listenAddr, loggedRouter)
}

// Ensures that the token has not been tampered with and verifies its authenticity. Not hardcoded.
var jwtKey = []byte(os.Getenv("JWT_SECRET"))

// Changed the Claims struct, so could identify claim using Id, JWT time and Role, not just id or name.
type Claims struct {
	UserID    int    `json:"user_id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	jwt.StandardClaims
}

func Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateUserInput(user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)
	user.ID = len(users) + 1
	users[user.ID] = user
	json.NewEncoder(w).Encode(user)
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var creds User
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var authenticatedUser *User
	for _, user := range users {
		if user.Username == creds.Username {
			err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password))
			if err != nil {
				http.Error(w, "Invalid credentials", http.StatusUnauthorized)
				return
			}
			authenticatedUser = &user
			break
		}
	}
	if authenticatedUser == nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	now := time.Now()
	claims := &Claims{
		UserID:   authenticatedUser.ID,
		Username: authenticatedUser.Username,
		Role:     authenticatedUser.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: now.Add(1 * time.Hour).Unix(),
			IssuedAt:  now.Unix(),
			NotBefore: now.Unix(),
			Issuer:    "bank-api",
			Subject:   strconv.Itoa(authenticatedUser.ID),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func UserHandler(w http.ResponseWriter, r *http.Request, claims *Claims) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid Request", http.StatusForbidden)
		return
	}
	if claims.Role != "admin" {
		http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
		return
	}
	json.NewEncoder(w).Encode(users)
}

func AccountsHandler(w http.ResponseWriter, r *http.Request, claims *Claims) {
	if claims.Role != "admin" {
		http.Error(w, "UnoAuthorized", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodPost:
		createAccount(w, r, claims)
		return
	case http.MethodGet:
		listAccounts(w, r, claims)
		return
	}
}
func createAccount(w http.ResponseWriter, r *http.Request, claims *Claims) {
	var acc Account
	if err := json.NewDecoder(r.Body).Decode(&acc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	acc.ID = len(accounts) + 1
	acc.CreatedAt = time.Now()
	accounts[acc.UserID] = acc
	json.NewEncoder(w).Encode(acc)
}

func listAccounts(w http.ResponseWriter, r *http.Request, claims *Claims) {
	json.NewEncoder(w).Encode(accounts)

}

func foo(w http.ResponseWriter, r *http.Request, claims *Claims){
	if claims.Role != "user" {
	http.Error(w, "UnoAuthorized", http.StatusNotFound)
	return
	}
	var body struct {
	UserID int     `json:"user_id"`
	UserID2 int     `json:"uid2"`
	Amount float64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	uid2, ok := users[uid2];
	if ok != nil{
		http.Error(w, "user2 not exist", http.StatusNotFound)
		}
	//check if possible to transfer his amount
		if accounts[claims.UserID].UserID == body.UserID {
			if body.Amount <= 0 {
				http.Error(w, "Amount must be greater than zero", http.StatusBadRequest)
				return
			}
			account := accounts[claims.UserID]
			if account.Balance < body.Amount {
				http.Error(w, "Insufficient funds", http.StatusBadRequest)
				return
			}
			account.Balance -= body.Amount
			accounts[claims.UserID] = account
			json.NewEncoder(w).Encode(account)
			return
		}

		//give uid2 amount money to its account
		account := accounts[uid2]
		account.Balance += body.Amount
		accounts[uid2] = account
		json.NewEncoder(w).Encode(account)
		return
	
	
	
	
	

	
	
}


func BalanceHandler(w http.ResponseWriter, r *http.Request, claims *Claims) {
	if claims.Role != "user" {
		http.Error(w, "UnoAuthorized", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		getBalance(w, r, claims)
	case http.MethodPost:
		depositBalance(w, r, claims)
	case http.MethodDelete:
		withdrawBalance(w, r, claims)
	}
}
func getBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	userId := r.URL.Query().Get("user_id")
	if userId == "" {
		http.Error(w, "Missing user_id parameter", http.StatusBadRequest)
		return
	}
	uid, err := strconv.Atoi(userId)
	if err != nil {
		http.Error(w, "Invalid user_id", http.StatusBadRequest)
		return
	}
	if claims.UserID != uid {
		http.Error(w, "Unauthorized access", http.StatusUnauthorized)
		return
	}

	if accounts[claims.UserID].UserID == uid {
		json.NewEncoder(w).Encode(map[string]float64{"balance": accounts[claims.UserID].Balance})
		return
	}
	http.Error(w, "Account not found", http.StatusNotFound)
}
func depositBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	var body struct {
		UserID int     `json:"user_id"`
		Amount float64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if claims.UserID != body.UserID {
		http.Error(w, "Unauthorized access", http.StatusUnauthorized)
		return
	}
	if accounts[claims.UserID].UserID == body.UserID {
		if body.Amount < 0 {
			http.Error(w, "Amount must be non-negative", http.StatusBadRequest)
			return
		}
		account := accounts[claims.UserID]
		account.Balance += body.Amount
		accounts[claims.UserID] = account
		json.NewEncoder(w).Encode(account)
		return
	}

	http.Error(w, "Account not found", http.StatusNotFound)
}

func withdrawBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	var body struct {
		UserID int     `json:"user_id"`
		Amount float64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if claims.UserID != body.UserID {
		http.Error(w, "Unauthorized access", http.StatusUnauthorized)
		return
	}

	if accounts[claims.UserID].UserID == body.UserID {
		if body.Amount <= 0 {
			http.Error(w, "Amount must be greater than zero", http.StatusBadRequest)
			return
		}
		account := accounts[claims.UserID]
		if account.Balance < body.Amount {
			http.Error(w, "Insufficient funds", http.StatusBadRequest)
			return
		}
		account.Balance -= body.Amount
		accounts[claims.UserID] = account
		json.NewEncoder(w).Encode(account)
		return
	}
	http.Error(w, "Account not found", http.StatusNotFound)
}
func Auth(next func(http.ResponseWriter, *http.Request, *Claims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if tokenStr == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}
		tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				http.Error(w, "Invalid signing method", http.StatusUnauthorized)
				return nil, fmt.Errorf("Invalid signing method")
			}
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if time.Unix(claims.ExpiresAt, 0).Before(time.Now()) {
			http.Error(w, "Token has expired", http.StatusUnauthorized)
			return
		}
		next(w, r, claims)
	}
}

// /////////////////Validators////////////////
func validateUserInput(user User) error {
	// Validate username
	if user.Username == "" || isUsernameTaken(user.Username) {
		return ErrUsernameMissing
	}

	// Validate role
	if err := validateRole(user); err != nil {
		return err
	}

	// Validate password
	if err := validatePassword(user.Password); err != nil {
		return err
	}

	return nil
}

// validateRole checks if the role is valid and if the user is trying to sign up as admin.
func validateRole(user User) error {
	validRoles := map[string]bool{"user": true, "admin": true}
	if !validRoles[user.Role] {
		return ErrInvalidRole
	}
	return nil
}

// validatePassword checks if the password meets the criteria.
// validatePassword checks if the password meets the minimum security requirements.
func validatePassword(password string) error {
	if len(password) < 8 {
		return ErrWeakPassword // Password must be at least 8 characters long
	}

	hasLetter := false
	for _, char := range password {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') {
			hasLetter = true
			break
		}
	}

	if !hasLetter {
		return ErrWeakPassword
	}

	return nil
}

// isUsernameTaken checks if the username already exists in the system.
func isUsernameTaken(username string) bool {
	for _, existingUser := range users {
		if strings.EqualFold(existingUser.Username, username) {
			return true
		}
	}
	return false
}
