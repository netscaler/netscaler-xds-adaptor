/*
Copyright 2020 Citrix Systems, Inc
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
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"
)

const (
	tcpTimeOut = 5 * time.Second
)

func StartTCPServer(port int) (net.Listener, error) {
	log.Printf("Starting TCP server at port %d", port)
	l, err := net.Listen("tcp", "0.0.0.0:"+fmt.Sprintf("%d", port))
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				log.Printf("TCP server accept failed : %v", err)
				return
			}
			reader := bufio.NewReader(conn)
			bytes, err1 := reader.ReadBytes(byte('\n'))
			if err1 != nil {
				if err1 != io.EOF {
					log.Println("TCP server failed to read data, err:", err1)
				}
				continue
			}
			log.Printf("TCP server received request: %s", bytes)

			line := fmt.Sprintf("%s", bytes)

			conn.Write([]byte(line))
			log.Printf("TCP server sent response: %s", line)
			conn.Close()
		}
	}()
	return l, nil
}

func StopTCPServer(l net.Listener) {
	log.Printf("Stopping TCP server")
	l.Close()
}

func DoTcpRequest(address string, port int, message string) (string, error) {
	conn, err := net.DialTimeout("tcp", address+":"+fmt.Sprintf("%d", port), tcpTimeOut)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if !strings.HasSuffix(message, "\n") {
		message = message + "\n"
	}
	_, err = conn.Write([]byte(message))
	if err != nil {
		return "", err
	}
	log.Printf("TCP client wrote request %s", message)
	reader := bufio.NewReader(conn)
	response, readErr := reader.ReadBytes(byte('\n'))
	if readErr != nil {
		return "", readErr
	}
	log.Printf("TCP client received response %s", fmt.Sprintf("%s", response))
	return strings.TrimSuffix(fmt.Sprintf("%s", response), "\n"), nil
}

func DoTcpSslRequest(address string, port int, message string, caCertLocation string) (string, error) {
	caCert, errCa := ioutil.ReadFile(caCertLocation)
	if errCa != nil {
		return "", errCa
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	conf := &tls.Config{RootCAs: caCertPool}
	dialer := &net.Dialer{
		Timeout: tcpTimeOut,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", address+":"+fmt.Sprintf("%d", port), conf)

	//	conn, err := tls.DialTimeout("tcp", address+":"+fmt.Sprintf("%d", port), conf, tcpTimeOut)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if !strings.HasSuffix(message, "\n") {
		message = message + "\n"
	}
	_, err = conn.Write([]byte(message))
	if err != nil {
		return "", err
	}
	log.Printf("TCP SSL client wrote request %s", message)
	reader := bufio.NewReader(conn)
	response, readErr := reader.ReadBytes(byte('\n'))
	if readErr != nil {
		return "", readErr
	}
	log.Printf("TCP SSL client received response %s", fmt.Sprintf("%s", response))
	return strings.TrimSuffix(fmt.Sprintf("%s", response), "\n"), nil
}
