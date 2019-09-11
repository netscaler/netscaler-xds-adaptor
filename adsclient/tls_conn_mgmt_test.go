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

package adsclient

import (
	"citrix-istio-adaptor/tests/env"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"google.golang.org/grpc"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func Test_getRootCAs(t *testing.T) {
	type EO struct {
		caCertPool *x509.CertPool
		err        error
	}

	caCert, err := ioutil.ReadFile("../tests/certs/tls_conn_mgmt_certs/root-cert.pem")
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
		{"../tests/certs/tls_conn_mgmt_certs/root-cert.pem", EO{tc1, nil}}, // Correct Root certificate
		{"doesnotexist-cert.pem", EO{nil, tc2Err}},                         // Certificate doesn't exist
		{"", EO{nil, nil}}, // No certificate file specified
		{"../tests/certs/tls_conn_mgmt_certs/key.pem", EO{nil, tc4Err}}, // Wrong certificate provided
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
	//parseErr := errors.New("Could not parse certificate")
	cases := []struct {
		input         EI
		expectedError error
	}{
		{EI{"../tests/certs/tls_conn_mgmt_certs/root-cert.pem",
			"spiffe://cluster.local/ns/istio-system/sa/istio-pilot-service-account",
			"../tests/certs/tls_conn_mgmt_certs/client-cert.pem",
			"../tests/certs/tls_conn_mgmt_certs/client-key.pem"}, nil,
		},
		{EI{"../tests/certs/tls_conn_mgmt_certs/root-cert.pem",
			"spiffe://cluster.local/ns/istio-system/sa/istio-pilot-service-account-wrong",
			"../tests/certs/tls_conn_mgmt_certs/client-cert.pem",
			"../tests/certs/tls_conn_mgmt_certs/client-key.pem"}, idMismatchErr,
		},
		{EI{"../tests/certs/tls_conn_mgmt_certs/cert-chain.pem",
			"spiffe://cluster.local/ns/istio-system/sa/istio-pilot-service-account",
			"../tests/certs/tls_conn_mgmt_certs/client-cert.pem",
			"../tests/certs/tls_conn_mgmt_certs/client-key.pem"}, verifyFailErr,
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
			if err != nil && err.Error() != c.expectedError.Error() {
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
		{EI{"localhost:15011", "spiffe://cluster.local/ns/istio-system/sa/istio-pilot-service-account", "../tests/certs/tls_conn_mgmt_certs/root-cert.pem", "../tests/certs/tls_conn_mgmt_certs/client-cert.pem", "../tests/certs/tls_conn_mgmt_certs/client-key.pem"},
			EO{nil, errors.New("connection error: desc = \"transport: error while dialing: dial tcp 127.0.0.1:15011: connect: connection refused\"")}},
		{EI{"localhost:15011", "spiffe://cluster.local/ns/istio-system/sa/istio-pilot-service-account", "../tests/certs/tls_conn_mgmt_certs/root-cert.pem", "../tests/certs/tls_conn_mgmt_certs/client-cert.pem", "emptyfile"},
			EO{nil, errors.New("tls: failed to find any PEM data in key input")}},
	}

	err := os.MkdirAll("/etc/certs", 0777)
	if err != nil {
		t.Fatalf("Could not create directory /etc/certs")
	}

	for _, c := range cases {
		err := copyFile(c.input.cacertfile, cacertFile)
		if err != nil {
			t.Errorf("Could not copy %s contents to %s. Err=%s", c.input.cacertfile, cacertFile, err)
		}
		err = copyFile(c.input.clientcertfile, clientCertFile)
		if err != nil {
			t.Errorf("Could not copy %s contents to %s. Err=%s", c.input.clientcertfile, clientCertFile, err)
		}
		err = copyFile(c.input.clientkeyfile, clientKeyFile)
		if err != nil {
			t.Errorf("Could not copy %s contents to %s. Err=%s", c.input.clientkeyfile, clientKeyFile, err)
		}
		conn, err := secureConnectToServer(c.input.address, c.input.spiffeID)
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
