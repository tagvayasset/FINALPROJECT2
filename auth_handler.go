package main

// import (
// 	"database/sql"
// 	"encoding/json"
// 	"net/http"
// 	"time"

// 	"github.com/dgrijalva/jwt-go"
// )

// type Login struct {
// 	UserID   string `json:"user_id"`
// 	Username string `json:"username"`
// 	Password string `json:"password"`
// 	Role     string `json:"role"`
// }

// type JWTClaims struct {
// 	Username string `json:"username"`
// 	Role     string `json:"role"`
// 	jwt.StandardClaims
// }

// var jwtKey = []byte("superSecret")

// func LoginHandler(db *sql.DB) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		if r.Method == http.MethodPost {
// 			var reqUser Login
// 			err := json.NewDecoder(r.Body).Decode(&reqUser)
// 			if err != nil {
// 				http.Error(w, err.Error(), http.StatusBadRequest)
// 				return
// 			}

// 			var userFromDB Login
// 			err = db.QueryRow("SELECT user_id, username, password, role FROM users WHERE username = $1 AND password = $2", reqUser.Username, reqUser.Password).Scan(&userFromDB.UserID, &userFromDB.Username, &userFromDB.Password, &userFromDB.Role)
// 			if err != nil && err != sql.ErrNoRows {
// 				http.Error(w, err.Error(), http.StatusInternalServerError)
// 				return
// 			}
// 			if userFromDB.Username == "" {
// 				http.Error(w, "Invalid username or password", http.StatusUnauthorized)
// 				return
// 			}

// 			//  JWT token
// 			expirationTime := time.Now().Add(1 * time.Hour) //  expires in 1 hour
// 			claims := &JWTClaims{
// 				Username: userFromDB.Username,
// 				Role:     userFromDB.Role,
// 				StandardClaims: jwt.StandardClaims{
// 					ExpiresAt: expirationTime.Unix(),
// 				},
// 			}
// 			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 			tokenString, err := token.SignedString(jwtKey)
// 			if err != nil {
// 				http.Error(w, err.Error(), http.StatusInternalServerError)
// 				return
// 			}

// 			// Return JWT token
// 			response := map[string]string{"token": tokenString}
// 			w.Header().Set("Content-Type", "application/json")
// 			json.NewEncoder(w).Encode(response)
// 		} else {
// 			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		}
// 	}
// }
