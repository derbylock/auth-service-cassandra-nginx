package main

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/julienschmidt/httprouter"
)

type authCreateRequestJSON struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

var jwtSecret []byte

var baseSalt *string
var jwtCookieName *string
var jwtExpirationSeconds *int

func createAuth(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var authCreateRequest authCreateRequestJSON
	if err := json.NewDecoder(r.Body).Decode(&authCreateRequest); err != nil {
		sendInvalidJSON(w, err)
		return
	}

	saltedPass := authCreateRequest.Password + *baseSalt
	sha_512 := sha512.New()
	sha_512.Write([]byte(saltedPass))

	passwordhash := hex.EncodeToString(sha_512.Sum(nil))

	log.Default().Println(passwordhash + " " + saltedPass + " " + authCreateRequest.Login)

	records, err := session.Query(`SELECT login FROM xgdb.auth WHERE login=? AND passwordhash=?`, authCreateRequest.Login, passwordhash).Iter().SliceMap()
	if err != nil {
		sendInvalidJSON(w, err)
		return
	}

	if len(records) > 0 {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"login":  authCreateRequest.Login,
			"status": "valid",
		})

		// Sign and get the complete encoded token as a string using the secret
		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			sendInvalidJSON(w, err)
			return
		}

		expiration := time.Now().Add(time.Duration(*jwtExpirationSeconds) * time.Second)
		cookie := http.Cookie{Name: *jwtCookieName, Value: tokenString, Expires: expiration}
		http.SetCookie(w, &cookie)
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
}

func checkAuth(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	tokenCookie, err := r.Cookie(*jwtCookieName)
	if err != nil {
		sendInvalidJSON(w, err)
		return
	}

	token, err := jwt.Parse(tokenCookie.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return jwtSecret, nil
	})

	if err != nil {
		sendInvalidJSON(w, err)
		return
	}

	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
	}
}
