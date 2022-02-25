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

package adsclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/citrix/citrix-xds-adaptor/tests/env"

	"google.golang.org/grpc"
)

func Test_getRootCAs(t *testing.T) {
	type EO struct {
		caCertPool *x509.CertPool
		err        error
	}

	caCert, err := ioutil.ReadFile("../tests/tls_conn_mgmt_certs/root-cert.pem")
	if err != nil {
		t.Errorf("[ERROR]: Could not read Root CA certificate. Err=%s", err)
	}
	tc1 := x509.NewCertPool()
	tc1.AppendCertsFromPEM(caCert)
	tc2Err := errors.New("open doesnotexist-cert.pem: no such file or directory")
	tc4Err := errors.New("failed to append ca certs")
	cases := []struct {
		input          string
		expectedOutput EO
	}{
		{"../tests/tls_conn_mgmt_certs/root-cert.pem", EO{tc1, nil}}, // Correct Root certificate
		{"doesnotexist-cert.pem", EO{nil, tc2Err}},                   // Certificate doesn't exist
		{"", EO{nil, nil}}, // No certificate file specified
		{"../tests/tls_conn_mgmt_certs/key.pem", EO{nil, tc4Err}}, // Wrong certificate provided
	}
	for _, c := range cases {
		cacertpool, err := getRootCAs(c.input)
		compare := true
		if err == nil {
			compare = reflect.DeepEqual(cacertpool, c.expectedOutput.caCertPool)
		}
		if err != nil && err.Error() != c.expectedOutput.err.Error() {
			t.Errorf("FAILED!!! Received error = %s Expected error = %s", err, c.expectedOutput.err)
		} else if compare == false {
			t.Errorf("FAILED!!! Expected: %v. Received: %v", c.expectedOutput.caCertPool, cacertpool)
		} else {
			t.Logf("PASSED for %v\n", c)
		}
	}
}

func loadTLSCertificates(clientCertFile, clientKeyFile string) ([]tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, err
	}

	return []tls.Certificate{cert}, nil
}

func Test_verifyPeerCertificate(t *testing.T) {
	type EI struct {
		CAfile       string
		spiffeID     string
		peerCertFile string
		peerKeyFile  string
	}

	idMismatchErr := errors.New("SPIFFE ID mismatch")
	verifyFailErr := errors.New("x509: certificate signed by unknown authority")
	certExpiryErr := errors.New("x509: certificate has expired or is not yet valid")
	//parseErr := errors.New("Could not parse certificate")
	cases := []struct {
		input         EI
		expectedError error
	}{
		{EI{"../tests/tls_conn_mgmt_certs/client-root-cert.pem",
			"spiffe://cluster.local/ns/httpbin/sa/httpbin",
			"../tests/tls_conn_mgmt_certs/client-cert.pem",
			"../tests/tls_conn_mgmt_certs/client-key.pem"}, nil,
		},
		{EI{"../tests/tls_conn_mgmt_certs/client-root-cert.pem",
			"spiffe://cluster.local/ns/httpbin/sa/httpbin-wrong",
			"../tests/tls_conn_mgmt_certs/client-cert.pem",
			"../tests/tls_conn_mgmt_certs/client-key.pem"}, idMismatchErr,
		},
		{EI{"../tests/tls_conn_mgmt_certs/cert-chain.pem",
			"spiffe://cluster.local/ns/httpbin/sa/httpbin",
			"../tests/tls_conn_mgmt_certs/client-cert.pem",
			"../tests/tls_conn_mgmt_certs/client-key.pem"}, verifyFailErr,
		},
	}

	for _, c := range cases {
		RootCAs, err := getRootCAs(c.input.CAfile)
		peer := &TLSPeer{
			SpiffeIDs:  []string{c.input.spiffeID},
			TrustRoots: RootCAs,
		}
		certChain, err := loadTLSCertificates(c.input.peerCertFile, c.input.peerKeyFile)
		for _, cert := range certChain {
			err = peer.verifyPeerCertificate(cert.Certificate, nil)
			if err != nil && err.Error() == certExpiryErr.Error() {
				t.Errorf("Certificate expired for %v. Update with latest certs", peer)
			} else if err != nil && strings.Contains(err.Error(), c.expectedError.Error()) == false {
				t.Errorf("Failed for peer %v. Received Err = %s. Expected Err = %s", peer, err, c.expectedError)
			} else {
				t.Logf("Passed for peer %v", peer)
			}
		}
	}
}

func copyFile(src, dst string) error {
	contents, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(dst, contents, 0644)
	if err != nil {
		return err
	}
	return nil
}

func Test_secureConnectToServer(t *testing.T) {
	type EI struct {
		address        string
		spiffeID       string
		cacertfile     string
		clientcertfile string
		clientkeyfile  string
	}
	type EO struct {
		conn *grpc.ClientConn
		err  error
	}

	if err := env.CreateAndWriteFile("emptyfile", ""); err != nil {
		t.Fatalf("Could not create emptyfile. Error: %s", err.Error())
	}
	cases := []struct {
		input          EI
		expectedOutput EO
	}{
		{EI{"localhost:15011", "spiffe://cluster.local/ns/httpbin/sa/httpbin", "../tests/tls_conn_mgmt_certs/client-root-cert.pem", "../tests/tls_conn_mgmt_certs/client-cert.pem", "../tests/tls_conn_mgmt_certs/client-key.pem"},
			EO{nil, errors.New("context deadline exceeded")}},
		{EI{"localhost:15011", "spiffe://cluster.local/ns/httpbin/sa/httpbin", "../tests/tls_conn_mgmt_certs/client-root-cert.pem", "../tests/tls_conn_mgmt_certs/client-cert.pem", "emptyfile"},
			EO{nil, errors.New("tls: failed to find any PEM data in key input")}},
	}

	err := os.MkdirAll("/etc/certs", 0777)
	if err != nil {
		t.Fatalf("Could not create directory /etc/certs")
	}

	err = os.MkdirAll("/etc/rootcert", 0777)
	if err != nil {
		t.Fatalf("Could not create directory /etc/rootcert")
	}

	for _, c := range cases {
		err := copyFile(c.input.cacertfile, CAcertFile)
		if err != nil {
			t.Errorf("Could not copy %s contents to %s. Err=%s", c.input.cacertfile, CAcertFile, err)
		}
		err = copyFile(c.input.clientcertfile, ClientCertFile)
		if err != nil {
			t.Errorf("Could not copy %s contents to %s. Err=%s", c.input.clientcertfile, ClientCertFile, err)
		}
		err = copyFile(c.input.clientkeyfile, ClientKeyFile)
		if err != nil {
			t.Errorf("Could not copy %s contents to %s. Err=%s", c.input.clientkeyfile, ClientKeyFile, err)
		}
		conn, err := secureConnectToServer(c.input.address, c.input.spiffeID, true)
		if err != nil && err.Error() != c.expectedOutput.err.Error() {
			t.Errorf("Received error %s. Expected error %s", err, c.expectedOutput.err)
		} else if err == nil {
			compare := reflect.DeepEqual(conn, c.expectedOutput.conn)
			if compare == true {
				t.Logf("Success for %v", c.input)
			} else {
				t.Errorf("Failed for %v", c.input)
			}
		}
	}
	if err := env.DeleteFile("emptyfile"); err != nil {
		t.Fatalf("Could not delete emptyfile. Error: %s", err.Error())
	}
}

func createDir(dir string) error {
	var _, err = os.Stat(dir)
	if os.IsNotExist(err) {
		err = os.Mkdir(dir, 0700)
		if err != nil {
			fmt.Printf("Could not create the config directory %s", dir)
			return err
		}
	}
	return nil
}

func Test_IsFileCreated(t *testing.T) {
	type EI struct {
		fileName   string
		expiryTime time.Duration
	}
	type EO struct {
		output      bool
		expectedErr string
	}
	testCases := map[string]struct {
		input          EI
		expectedOutput EO
	}{
		"File Created": {
			input:          EI{"dir1/file1", 5},
			expectedOutput: EO{true, ""},
		},
		"Desired file not created. Timeout": {
			input:          EI{"dir1/file2", 2},
			expectedOutput: EO{false, ""},
		},
		"Directory does not exist": {
			input:          EI{"imaginary/file", 2},
			expectedOutput: EO{false, "Directory imaginary does not seem to be mounted"},
		},
	}
	if err := createDir("dir1"); err != nil {
		t.Fatalf("Could not create dir1 directory. Error: %s", err.Error())
	}

	for id, c := range testCases {
		if id != "Directory does not exist" {
			go func(filepath string) {
				time.Sleep(500 * time.Millisecond)
				message := []byte("randomstring")
				err := ioutil.WriteFile(filepath, message, 0644)
				if err != nil {
					t.Fatalf("Could not create file %s. Error: %s", filepath, err.Error())
				} else {
					t.Logf("%s file created at %s", filepath, time.Now().String())
				}
			}(c.input.fileName)
		}
		output, err := IsFileCreated("dir1/file1", c.input.expiryTime)
		if err != nil && err.Error() != c.expectedOutput.expectedErr {
			t.Errorf("%s: expected error: %s, received: %s\n", id, c.expectedOutput.expectedErr, err.Error())
		} else if output != c.expectedOutput.output {
			t.Errorf("%s, expected: %v, received: %v\n", id, c.expectedOutput.output, output)
		} else {
			t.Logf("%s. Success!", id)
		}
	}
	if err := os.RemoveAll("dir1"); err != nil {
		t.Logf("Could not delete dir1")
	}
}
