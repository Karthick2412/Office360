package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func ProfileSetting(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Hello there")
	w.Header().Set("Content-Type", "application/json")
	fmt.Println("Working fine")
	json.NewEncoder(w).Encode("Hello there")

}
