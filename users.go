package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
)

func UsersHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			rows, err := db.Query("SELECT * FROM users")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer rows.Close()

			var users []string
			for rows.Next() {
				var userID string
				var username string
				var password string
				var role string
				if err := rows.Scan(&userID, &username, &password, &role); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				users = append(users, fmt.Sprintf("user_id: %s, username: %s, password: %s, role: %s", userID, username, password, role))
			}

			if err := rows.Err(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(users)
		} else {
			// Respond with method not allowed error
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}
