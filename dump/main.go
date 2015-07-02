// Dump all incomming requests
package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := httputil.DumpRequest(r, true)
		fmt.Println(string(body))
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
