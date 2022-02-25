/*
Copyright 2022 Citrix Systems, Inc
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

package env

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
)

const (
	httpTimeOut = 5 * time.Second
)

func httpPathHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s!", r.URL.Path[1:])
}

type pathHandler struct {
	message string
}

func (ph *pathHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(ph.message))
}

// StartHTTPServer starts a http server at given port and accepts requests at path
func StartHTTPServer(port int, path string, msg string) (*http.Server, error) {
	log.Printf("Starting HTTP server at port %d, path %s", port, path)
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	log.Printf("Listening HTTP/1.1 on %v\n", port)
	mux := http.NewServeMux()
	ph := &pathHandler{message: msg}
	mux.Handle(path, ph)
	srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux}

	go func() {
		if err := srv.Serve(ln); err != nil {
		}
	}()
	return srv, nil
}

// StopHTTPServer stops a http server
func StopHTTPServer(httpServer *http.Server) {
	httpServer.Close()
}

// DoHTTPGet performs a HTTP GET operation on a URL
func DoHTTPGet(url string) (code int, respBody string, err error) {
	log.Println("HTTP GET", url)
	client := &http.Client{Timeout: httpTimeOut,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		log.Println(err)
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return 0, "", err
	}
	respBody = string(body)
	code = resp.StatusCode
	log.Println(respBody)
	return code, respBody, nil
}

func DoHTTPGetAll(url string) (*http.Response, error) {
	log.Println("HTTP GET", url)
	client := &http.Client{Timeout: httpTimeOut,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	resp.Body.Close()
	return resp, nil
}

func DoHTTPSGet(url string, caCertLocation string) (code int, respBody string, err error) {
	log.Println("HTTPS GET", url)
	client := &http.Client{Timeout: httpTimeOut}
	if caCertLocation != "" {
		caCert, err := ioutil.ReadFile(caCertLocation)
		if err != nil {
			return 0, "", err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		}
	}

	resp, err := client.Get(url)
	if err != nil {
		return 0, "", err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return 0, "", err
	}
	respBody = string(body)
	code = resp.StatusCode
	log.Println(respBody)
	return code, respBody, nil

}
