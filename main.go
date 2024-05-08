package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"
)

func main() {

	db, err := ConnectDB()

	if err != nil {
		return
	}

	defer db.Close()

	http.HandleFunc("/users", jwtMiddleware(UsersHandler(db), "admin"))

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var reqUser Login
			err := json.NewDecoder(r.Body).Decode(&reqUser)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			var userFromDB Login
			err = db.QueryRow("SELECT user_id, username, password, role FROM users WHERE username = $1 AND password = $2", reqUser.Username, reqUser.Password).Scan(&userFromDB.UserID, &userFromDB.Username, &userFromDB.Password, &userFromDB.Role)
			if err != nil && err != sql.ErrNoRows {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if userFromDB.Username == "" {
				http.Error(w, "Invalid username or password", http.StatusUnauthorized)
				return
			}

			//  JWT token
			expirationTime := time.Now().Add(1 * time.Hour) //  expires in 1 hour
			claims := &JWTClaims{
				Username: userFromDB.Username,
				Role:     userFromDB.Role,
				StandardClaims: jwt.StandardClaims{
					ExpiresAt: expirationTime.Unix(),
				},
			}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString(jwtKey)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Return JWT token
			response := map[string]string{"token": tokenString}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/menu", jwtMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			rows, err := db.Query("SELECT * FROM menu")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer rows.Close()

			var items []string
			for rows.Next() {
				var id string
				var name string
				var description string
				var price string
				if err := rows.Scan(&id, &name, &description, &price); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				items = append(items, fmt.Sprintf("id: %s, name: %s, description: %s, price: %s", id, name, description, price))
			}

			if err := rows.Err(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(items)
		} else {
			// Respond with method not allowed error
			w.WriteHeader(http.StatusMethodNotAllowed)
		}

	}, "customer", "admin"))

	http.HandleFunc("/orders", jwtMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			rows, err := db.Query("SELECT * FROM orders")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer rows.Close()

			var orders []string
			for rows.Next() {
				var orderid string
				var userid string
				var itemname string
				var price string
				if err := rows.Scan(&orderid, &userid, &itemname, &price); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				orders = append(orders, fmt.Sprintf("orderid: %s, userid: %s, itemname: %s, price: %s", orderid, userid, itemname, price))
			}

			if err := rows.Err(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(orders)
		} else {
			// Respond with method not allowed error
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}, "admin"))

	http.HandleFunc("/make-order", jwtMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var reqOrd Order
			err := json.NewDecoder(r.Body).Decode(&reqOrd)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			fmt.Print(reqOrd.Itemid)

			// Get the claims from the request context
			tokenHeader := r.Header.Get("Authorization")

			if tokenHeader == "" || !strings.HasPrefix(tokenHeader, "Bearer ") {
				http.Error(w, "No token provided", http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(tokenHeader, "Bearer ")

			token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
				return jwtKey, nil
			})

			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			if !token.Valid {
				http.Error(w, "Token is not valid", http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(*JWTClaims)
			if !ok {
				http.Error(w, "Invalid claims", http.StatusUnauthorized)
				return
			}

			username := claims.Username

			var existingItem Item
			err = db.QueryRow("SELECT id, name, description, price  FROM menu WHERE id = $1", reqOrd.Itemid).Scan(&existingItem.Id, &existingItem.Name, &existingItem.Description, &existingItem.Price)
			if err != nil && err != sql.ErrNoRows {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if existingItem.Name == "" {
				http.Error(w, "Item doesn't exist", http.StatusConflict)
				return
			}

			_, err = db.Exec("INSERT INTO orders (username, itemname, status) VALUES ($1, $2, $3)", username, existingItem.Name, "done")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("Order made successfully"))

		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}, "customer"))

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var reqUser Login
			err := json.NewDecoder(r.Body).Decode(&reqUser)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// Check username already exists
			var existingUser Login
			err = db.QueryRow("SELECT user_id, username, password, role FROM users WHERE username = $1", reqUser.Username).Scan(&existingUser.UserID, &existingUser.Username, &existingUser.Password, &existingUser.Role)
			if err != nil && err != sql.ErrNoRows {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if existingUser.Username != "" {
				http.Error(w, "Username already exists", http.StatusConflict)
				return
			}

			// insert the new user
			_, err = db.Exec("INSERT INTO users (username, password, role) VALUES ($1, $2, $3)", reqUser.Username, reqUser.Password, reqUser.Role)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("User registered successfully"))
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/change-menu", jwtMiddleware(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Handling change-menu request...")
	}, "admin"))

	// Start the HTTP server
	log.Println("Server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

type JWTClaims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

var jwtKey = []byte("superSecret")
