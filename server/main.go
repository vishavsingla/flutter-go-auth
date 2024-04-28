package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"
	"github.com/joho/godotenv"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	ID              string    `gorm:"primaryKey"`
	Name            string    `gorm:"not null"`
	Email           string    `gorm:"unique;not null"`
	EmailVerified   time.Time `gorm:"default:null"`
	HashedPassword  string    `gorm:"not null"`
	ExpiresAt       int       `gorm:"default:null"`
	TokenType       string    `gorm:"default:null"`
	Scope           string    `gorm:"default:null"`
	IDToken         string    `gorm:"default:null"`
	SessionState    string    `gorm:"default:null"`
	CreatedAt       time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt       time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	Sessions        []Session
	VerificationTokens []VerificationToken
}

type Session struct {
	ID           string             `gorm:"primaryKey"`
	SessionToken string             `gorm:"unique;not null"`
	UserID       string             `gorm:"not null"`
	AccessToken  string             `gorm:"default:null"`
	RefreshToken string             `gorm:"default:null"`
	VerificationTokens []VerificationToken `gorm:"foreignKey:SessionID"`
	Expires      time.Time          `gorm:"default:time.Now().Add(1),"`
	User         User               `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

type VerificationToken struct {
	Identifier string    `gorm:"primaryKey"`
	Token      string    `gorm:"unique;not null"`
	Expires    time.Time `gorm:"not null"`
	UserID     string    `gorm:"not null"`
	User       User      `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	SessionID  *string   `gorm:"default:null"`
	Session    *Session  `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

type SignUpRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Response struct {
	Message           string            `json:"message"`
	User              User              `json:"user"`
	VerificationToken VerificationToken `json:"verificationToken"`
}

var db *gorm.DB

func main() {
	port := "3001"

	databaseURL := "postgres://postgres:123@localhost:5432/testapp"

	var err error
	db, err = gorm.Open(postgres.Open(databaseURL), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	db.AutoMigrate(&User{}, &Session{}, &VerificationToken{})

	corsHandler := corsMiddleware(http.HandlerFunc(handleRoot))
    http.Handle("/", corsHandler)
    http.Handle("/auth/user/signup", corsMiddleware(http.HandlerFunc(handleSignUp)))
    http.Handle("/auth/user/login", corsMiddleware(http.HandlerFunc(loginHandler)))
    http.Handle("/auth/user/logout", corsMiddleware(http.HandlerFunc(handleLogout)))
    http.Handle("/auth/user/refresh-token", corsMiddleware(http.HandlerFunc(handleRefreshToken)))
    http.Handle("/auth/user/check-session", corsMiddleware(http.HandlerFunc(checkValidSessionHandler)))
    http.Handle("/auth/user/user", corsMiddleware(http.HandlerFunc(getUserDetailsHandler)))

    log.Printf("Server running on :%s", port)
    log.Fatal(http.ListenAndServe("localhost:"+port, nil))

}

func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Set the CORS headers
        w.Header().Set("Access-Control-Allow-Origin", "*") // Adjust this to your specific needs
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

        // Handle preflight requests
        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusOK)
            return
        }

        // Call the next handler
        next.ServeHTTP(w, r)
    })
}


func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Go Server")
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func generateVerificationToken() string {
	return uuid.New().String()
}

func handleSignUp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SignUpRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.Email == "" || req.Password == "" {
		http.Error(w, "Please provide all required fields", http.StatusBadRequest)
		return
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	user := User{
		ID:             uuid.New().String(),
		Name:           req.Name,
		Email:          req.Email,
		HashedPassword: hashedPassword,
	}

	if err := db.Create(&user).Error; err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	verificationToken := VerificationToken{
		Identifier: user.Email,
		Token:      generateVerificationToken(),
		Expires:    time.Now().Add(24 * time.Hour),
		UserID:     user.ID,
	}

	if err := db.Create(&verificationToken).Error; err != nil {
		http.Error(w, "Failed to create verification token", http.StatusInternalServerError)
		return
	}

	response := Response{
		Message:           "User registered successfully",
		User:              user,
		VerificationToken: verificationToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}


func loginHandler(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	existingUser := &User{}
	result := db.Where("email = ?", credentials.Email).First(existingUser)
	if result.RowsAffected == 0 {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(existingUser.HashedPassword), []byte(credentials.Password))
	if err != nil {
		http.Error(w, "Incorrect password", http.StatusBadRequest)
		return
	}

	accessToken, err := generateAccessToken(existingUser.ID, 1*time.Minute)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	refreshToken, err := generateRefreshToken(existingUser.ID, 24*time.Hour)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sessionToken := generateSessionToken()

	session := Session{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		SessionToken: sessionToken,
		UserID:       existingUser.ID,
		Expires:      time.Now().Add(7 * 24 * time.Hour),
	}
	result = db.Create(&session)
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "accessToken",
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "sessionToken",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":     "Login successful",
		"accessToken": accessToken,
		"session":     session,
	})
}


func handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionToken, err := r.Cookie("sessionToken")
	if err != nil {
		http.Error(w, "Not Logged In", http.StatusUnauthorized)
		return
	}

	result := db.Where("session_token = ?", sessionToken.Value).Delete(&Session{})
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "accessToken",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		MaxAge:   -1,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "sessionToken",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		MaxAge:   -1,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Logged out successfully",
	})
}

func handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	sessionToken, err := r.Cookie("sessionToken")
	if err != nil {
		http.Error(w, "Not Logged In", http.StatusUnauthorized)
		return
	}

	session := &Session{}
	result := db.Where("session_token = ?", sessionToken.Value).First(session)
	if result.RowsAffected == 0 {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	refreshToken := session.RefreshToken

	privateKey := os.Getenv("REFRESH_TOKEN_PRIVATE_KEY")

	decoded, err := jwt.ParseWithClaims(refreshToken, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(privateKey), nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	claims, ok := decoded.Claims.(*jwt.MapClaims)
	if !ok || !decoded.Valid {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	id := (*claims)["userID"].(string)
	
	newAccessToken, err := generateAccessToken(id, 1*time.Minute)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newSessionToken := generateSessionToken()

	session.AccessToken = newAccessToken
	session.SessionToken = newSessionToken
	session.Expires = time.Now().Add(7 * 24 * time.Hour)

	result = db.Save(session)
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "accessToken",
		Value:    newAccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "sessionToken",
		Value:    newSessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
	})

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "Token refreshed successfully",
		"accessToken":  newAccessToken,
		"sessionToken": newSessionToken,
	})
}

func checkValidSessionHandler(w http.ResponseWriter, r *http.Request) {
	sessionToken, err := r.Cookie("sessionToken")
	if err != nil {
		http.Error(w, "Not Logged In", http.StatusUnauthorized)
		return
	}

	session := &Session{}
	result := db.Where("session_token = ? AND expires_at > ?", sessionToken.Value, time.Now()).First(session)
	if result.RowsAffected == 0 {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"success": "Is logged in",
	})
}

func getUserDetailsHandler(w http.ResponseWriter, r *http.Request) {
	sessionToken, err := r.Cookie("sessionToken")
	if err != nil {
		http.Error(w, "Not Logged In", http.StatusUnauthorized)
		return
	}

	session := &Session{}
	result := db.Where("session_token = ?", sessionToken.Value).First(session)
	if result.RowsAffected == 0 {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}

	user := &User{}
	result = db.First(user, session.UserID)
	if result.RowsAffected == 0 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

func generateAccessToken(userID string, duration time.Duration) (string, error) {
	claims := jwt.MapClaims{}
	claims["userID"] = userID
	claims["exp"] = time.Now().Add(duration).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	privateKey := os.Getenv("ACCESS_TOKEN_PRIVATE_KEY")

	tokenString, err := token.SignedString([]byte(privateKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func generateRefreshToken(userID string, duration time.Duration) (string, error) {
	claims := jwt.MapClaims{}
	claims["userID"] = userID
	claims["exp"] = time.Now().Add(duration).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	privateKey := os.Getenv("REFRESH_TOKEN_PRIVATE_KEY")

	tokenString, err := token.SignedString([]byte(privateKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
var seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))

func generateSessionToken() string {
	
	const letters = "abcdefghijklmpqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 15)
	for i := range b {
		b[i] = letters[seededRand.Intn(len(letters))]
	}
	return string(b)
}
