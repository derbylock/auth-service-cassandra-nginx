package xgservice

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"io"
	"math/rand"
)

type authCreateRequestJSON struct {
	login    string `json:"login"`
	password string `json:"password"`
}

var baseSalt = "haidu#41312#gohk"
var jwtSecret []byte

func createAuth(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var authCreateRequest authCreateRequestJSON
	if err := json.NewDecoder(r.Body).Decode(&authCreateRequest); err != nil {
		sendInvalidJSON(w, err)
		return
	}

	saltedPass := input + baseSalt
	passwordhash := sha512.New(sha_512.Write([]byte(saltedPass))).Sum(nil)

	records, err := session.Query(`SELECT login FROM xgdb.auth WHERE login=? AND passwordhash=?`, id, sha_512).Iter().SliceMap()
	if err != nil {
		sendInvalidJSON(w, err)
		return
	}

	if len(records) > 0 {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"foo": "bar",
			"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
		})

		// Sign and get the complete encoded token as a string using the secret
		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			sendInvalidJSON(w, err)
			return
		}

		expiration := time.Now().Add(24 * time.Hour)
		cookie := http.Cookie{Name: "xgtoken", value: tokenString, Expires: expiration}
		http.SetCookie(w, &cookie)
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
}

func checkAuth(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	tokenCookie, err := r.Cookie("xgtoken")
	if err != nil {
		sendInvalidJSON(w, err)
		return
	}

	token, err := jwt.Parse(tokenCookie, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return jwtSecret, nil
	})

	if err != nil {
		sendInvalidJSON(w, err)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
	}
}
