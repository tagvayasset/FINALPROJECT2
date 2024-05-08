package main

import (
	"database/sql"
	"log"
)

func ConnectDB() (*sql.DB, error) {
	db, err := sql.Open("postgres", "postgres://root:root@localhost/test_db?sslmode=disable")
	if err != nil {
		log.Fatal(err)
		return db, err
	}

	return db, nil
}
