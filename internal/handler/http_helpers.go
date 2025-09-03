	package handler

	import (
		"encoding/json"
		"net/http"
	)

	func writeJSON(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}

	func writeJSONError(w http.ResponseWriter, status int, message string) {
		writeJSON(w, status, map[string]any{
			"error": map[string]any{
				"code":    status,
				"message": message,
			},
		})
	}
