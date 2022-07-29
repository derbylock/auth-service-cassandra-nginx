package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type errorJSON struct {
	ErrorMessage string `json:"message"`
}

func renderError(w http.ResponseWriter, message string, statusCode int) {
	responseJSON := errorJSON{ErrorMessage: message}

	response, err := json.Marshal(responseJSON)
	if err != nil {
		sendInternalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Connection", "close")
	w.WriteHeader(statusCode)
	w.Write(response)
}

func sendInternalError(w http.ResponseWriter, err error) {
	log.Println(err)
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusInternalServerError)
}

func sendInvalidJSON(w http.ResponseWriter, err error) {
	log.Println(err)
	w.WriteHeader(http.StatusBadRequest)
}

func sendBadRequest(w http.ResponseWriter) {
	w.WriteHeader(http.StatusBadRequest)
}
