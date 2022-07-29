package xgservice

import (
	"encoding/json"
	"net/http"
	"syscall"

	"github.com/julienschmidt/httprouter"
)

type healthResponse struct {
	Status              string `json:"status"`
	BuildID             string `json:"buildId"`
	RepoFolderSize      uint64 `json:"repoFolderSize"`
	RepoFolderAvailable uint64 `json:"repoFolderAvailable"`
}

func getHealth(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var statFiles syscall.Statfs_t
	syscall.Statfs(*repoPath, &statFiles)

	resp := healthResponse{
		Status:              "Healthy",
		BuildID:             *buildNumber,
		RepoFolderSize:      uint64(statFiles.Bsize) * statFiles.Blocks,
		RepoFolderAvailable: uint64(statFiles.Bsize) * statFiles.Bavail}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		sendInternalError(w, err)
	}
}
