package main

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gocql/gocql"
	"github.com/golang-jwt/jwt/v4"
	"github.com/julienschmidt/httprouter"
)

type authCreateRequestJSON struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type changePasswordRequestJSON struct {
	Login       string `json:"login"`
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

type createUserRequestJSON struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	Groups   string `json:"groups"`
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

	records, err := session.Query(`SELECT groups FROM xgdb.auth WHERE login=? AND passwordhash=?`, authCreateRequest.Login, passwordhash).Iter().SliceMap()
	if err != nil {
		sendInvalidJSON(w, err)
		return
	}

	if len(records) > 0 {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"login":  authCreateRequest.Login,
			"status": "valid",
			"groups": (records[0])["groups"].(string),
		})

		// Sign and get the complete encoded token as a string using the secret
		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			sendInvalidJSON(w, err)
			return
		}

		expiration := time.Now().Add(time.Duration(*jwtExpirationSeconds) * time.Second)
		cookie := http.Cookie{Name: *jwtCookieName, Value: tokenString, Path: "/", Expires: expiration, Domain: strings.Split(r.Host, ":")[0]}
		http.SetCookie(w, &cookie)
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
}

func logout(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	cookie := http.Cookie{Name: *jwtCookieName, Value: "", Path: "/", MaxAge: 0, Domain: strings.Split(r.Host, ":")[0]}
	http.SetCookie(w, &cookie)
	w.WriteHeader(http.StatusOK)
}

func checkAuth(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	tokenCookie, err := r.Cookie(*jwtCookieName)
	if err != nil {
		sendUnauthorizedErr(w, err)
		return
	}

	token, err := jwt.Parse(tokenCookie.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return jwtSecret, nil
	})

	if err != nil {
		sendUnauthorizedErr(w, err)
		return
	}

	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
	}
}

func checkAdminAuth(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	admin, err := isAdmin(r)
	if err != nil {
		sendUnauthorizedErr(w, err)
		return
	}

	if admin {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
	}
}

func isAdmin(r *http.Request) (bool, error) {
	tokenCookie, err := r.Cookie(*jwtCookieName)
	if err != nil {
		return false, err
	}

	token, err := jwt.Parse(tokenCookie.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return jwtSecret, nil
	})

	if err != nil {
		return false, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if strings.Contains(claims["groups"].(string), "admin") {
			return true, nil
		} else {
			return false, nil
		}
	} else {
		return false, nil
	}
}

func getLogin(r *http.Request) (string, error) {
	tokenCookie, err := r.Cookie(*jwtCookieName)
	if err != nil {
		return "", err
	}

	token, err := jwt.Parse(tokenCookie.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return jwtSecret, nil
	})

	if err != nil {
		return "", err
	}

	if claim, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claim["login"].(string), nil
	} else {
		return "", nil
	}
}

func changePassword(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	login, err := getLogin(r)
	if err != nil {
		sendInvalidJSON(w, err)
		return
	}

	if login == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var changePasswordRequest changePasswordRequestJSON
	if err := json.NewDecoder(r.Body).Decode(&changePasswordRequest); err != nil {
		sendInvalidJSON(w, err)
		return
	}

	if login != changePasswordRequest.Login {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	saltedPassOld := changePasswordRequest.OldPassword + *baseSalt
	sha_512 := sha512.New()
	sha_512.Write([]byte(saltedPassOld))
	oldPasswordhash := hex.EncodeToString(sha_512.Sum(nil))

	saltedPassNew := changePasswordRequest.NewPassword + *baseSalt
	sha_512_2 := sha512.New()
	sha_512_2.Write([]byte(saltedPassNew))
	newPasswordhash := hex.EncodeToString(sha_512.Sum(nil))

	err = session.Query(`UPDATE xgdb.auth SET passwordhash=? WHERE login=? AND passwordhash=?`,
		oldPasswordhash,
		changePasswordRequest.Login,
		newPasswordhash).Consistency(gocql.Quorum).Exec()
	if err != nil {
		sendInvalidJSON(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func createUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	admin, err := isAdmin(r)
	if err != nil {
		sendInvalidJSON(w, err)
		return
	}

	if !admin {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var createUserRequest createUserRequestJSON
	if err := json.NewDecoder(r.Body).Decode(&createUserRequest); err != nil {
		sendInvalidJSON(w, err)
		return
	}

	saltedPass := createUserRequest.Password + *baseSalt
	sha_512 := sha512.New()
	sha_512.Write([]byte(saltedPass))
	passwordhash := hex.EncodeToString(sha_512.Sum(nil))

	err = session.Query(`INSERT INTO xgdb.auth (login, password, groups) VALUES (?, ?, ?)`,
		createUserRequest.Login,
		passwordhash,
		createUserRequest.Groups).Consistency(gocql.Quorum).Exec()
	if err != nil {
		sendInvalidJSON(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}
