// Deliberately unsafe — benchmark fixture only.
package main

import (
	"crypto/tls"
	"net/http"
	"os/exec"
)

func client() *http.Client {
	cfg := &tls.Config{InsecureSkipVerify: true}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func run(userInput string) ([]byte, error) {
	return exec.Command("sh", "-c", userInput).Output()
}

func cors(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
}
