package main

import (
	"encoding/json"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

type healthResponse struct {
	Status  string `json:"status"`
	BuildID string `json:"buildId"`
}

func getHealth(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	resp := healthResponse{
		Status:  "Healthy",
		BuildID: *buildNumber,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		sendInternalError(w, err)
	}
}
