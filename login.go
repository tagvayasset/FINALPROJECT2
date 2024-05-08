package main

type Login struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}
