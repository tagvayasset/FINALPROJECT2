package main

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
)

func jwtMiddleware(next http.HandlerFunc, allowedRoles ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		roleAllowed := false
		for _, allowedRole := range allowedRoles {
			if claims.Role == allowedRole {
				roleAllowed = true
				break
			}
		}

		if !roleAllowed {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}
