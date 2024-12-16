package main

import "net/http"

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
	type returnVals struct {
		Message string `json:"message"`
	}

	if cfg.platform != "dev" {
		respondWithJSON(w, http.StatusForbidden, returnVals{
			Message: "Reset is only allowed in dev environment",
		})
		return
	}

	if err := cfg.db.DeleteAllUsers(r.Context()); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't delete all users", err)
		return
	}

	cfg.fileserverHits.Store(0)

	respondWithJSON(w, http.StatusOK, returnVals{
		Message: "All users deleted successfully",
	})
}
