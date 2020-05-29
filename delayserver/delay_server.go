/*
Copyright 2019 Citrix Systems, Inc
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package delayserver

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"
)

const delayServerPort = "10093"

//startDelayServer is a global variable to start HTTP server to handle Delay
var startDelayServer bool = true

func headers(w http.ResponseWriter, req *http.Request) {
	keys, _ := req.URL.Query()["sleep"]
	key := keys[0]
	sleep, _ := strconv.Atoi(key)
	time.Sleep(time.Duration(sleep) * time.Second)
	fmt.Fprintf(w, "Done\n")
	log.Printf("[DEBUG] Sleep for %s Seconds", key)
}

//StartDelayServer will start a server
func StartDelayServer() {
	if startDelayServer {
		go startHTTPDelayServer()
		startDelayServer = false
	}
	return
}

//startHTTPDelayServer starts
func startHTTPDelayServer() {
	http.HandleFunc("/", headers)
	err := http.ListenAndServe(":"+delayServerPort, nil)
	if err != nil {
		log.Printf("[ERROR] Couldn't Start the Delay Server %v", err)
	}
}
