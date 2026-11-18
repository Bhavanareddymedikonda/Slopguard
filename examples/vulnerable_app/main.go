package main

import (
	"crypto/tls"
	"net/http"
	"os"
)

func main() {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	_ = tr
	_, _ = os.Open("/tmp/x")
	// FIXME: handle errors properly
	if err != nil {
	}
}
