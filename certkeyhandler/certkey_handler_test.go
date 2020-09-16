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

package certkeyhandler

import (
	"bytes"
	"citrix-xds-adaptor/tests/env"
	"context"
	"fmt"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc"
	pb "istio.io/istio/security/proto"
)

const mockServerAddress = "localhost:0"

var (
	certDir       = "/etc/certs"
	fakeCert      = []string{"fake", "certificate"}
	fakeTokenFile = "/tmp/tokenfile"
	fakeToken     = "Bearer fakeToken"
	validCert     = []string{`-----BEGIN CERTIFICATE-----
MIIDIzCCAgugAwIBAgIQItm6wbnrdeNqjQT5kxlgxDANBgkqhkiG9w0BAQsFADAY
MRYwFAYDVQQKEw1jbHVzdGVyLmxvY2FsMB4XDTIwMDkxNDA5MDQ0OVoXDTIwMTIx
MzA5MDQ0OVowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL+LwKDT
3Hfj4WlwGOItxprSpisZQQ8QpubXLmmy9WGWe3lrgwRJ7cS1bOHEsQAr4gAFAgX8
wyl2ZdpllwGDwDzGgJuvNWs9kDyU1iHXe119nSu0o8WJw2TXPVBOhtmYKAaKxgIi
2r1n9ptm1+6fJcXD6yCwdHXC0sod08QaQVduzCDLvKfROsJsccu3cWFblpT/DtoS
HAKlOXfT1vY8A++CJPycONVcqDyg4rGtuCoL5YSVuoR5pV1BgDGtavLaBjah2SE0
/XHAkAaLHF2hNHijCXOmYgUo/fNmxC2leaq+5Qekrvj0RB94MMymz/9PNKu47F8H
n9l2Uf/WC6ARcWcCAwEAAaOBgDB+MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAU
BggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADA/BgNVHREBAf8ENTAz
hjFzcGlmZmU6Ly9jbHVzdGVyLmxvY2FsL25zL2lzdGlvMTYwLWNweC9zYS9odHRw
YmluMA0GCSqGSIb3DQEBCwUAA4IBAQCRbtjUvhPjFZEtFwItpYXCU7454804OFh2
MU39ZNi3pUr32dnk+EWaZEOAi8tymNqn5PzuGctmnw4fUe46Rp6+E8FHvBeH5eew
bMIO37ucHJRcC9EbPC4S+me+nD0ZD8dy0iUjUcAOsM3HuA1f5WOU57zGWYZ6aOTN
GHvcJ1SYcO7q8hffG/NdHuYGdssjUfeYGWQiZM60vfKyIQ6Q6osP3io0zZMfWASx
UBmO6JpyD0J3pCmbgoHHCx+xRR0XtByj5x7tc+lbJ85i4Ydg+Qy8xxOzmLvYyrMB
BYY1ZyPthpUJciiIY5rKb8KsdJa/tEXDzrsFXG/xHsbzvU4MN9Sd
-----END CERTIFICATE-----
`,
		`-----BEGIN CERTIFICATE-----
MIIC3TCCAcWgAwIBAgIQEYoJlkp1aw5hTUF4GUTOWzANBgkqhkiG9w0BAQsFADAY
MRYwFAYDVQQKEw1jbHVzdGVyLmxvY2FsMB4XDTIwMDcwMjA4NTUwMFoXDTMwMDYz
MDA4NTUwMFowGDEWMBQGA1UEChMNY2x1c3Rlci5sb2NhbDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBALsG1co6zMLVyLRTKiSS15o06ftqLyZSH7Abi04T
5gMVlD6QQnz8C0dmNUhMAwNHivVHseWTqogX2WftzGxex8rkIVWbCrTonClZCvti
nuvly42EeZnl100O4iRsF9fQJviMqpj+VVSs8bG539cprgiIABgDvmWeovJ837UP
/bM2pHWkg9uq9hMs64RCKuWMv8hpC+j2akTnAzWAFhvpJKfzTlddYmXM26SYs+rK
VIrA4GRPDXW69y3O6pCBU0JFYqNf2GL1vUSRnAMLgBF4qFyT2r+yzhCG7S+g6Myg
p8VJK9v30kqbRvS/kx3pL4nwdfdW8WbpcVHcN6h+VAee/OUCAwEAAaMjMCEwDgYD
VR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
AGwsM5X5BYbIIuA9P/hdRYxgN3gzg8e1smS7teZAbpHb/1O8dv3EclH8W2bktXmV
FHSS9Tg3OrEVE1f4jimXjTpepB+tJL6R+SNFEmGiM8uTe5QpDDn5XH0+8k5J6xAJ
JmIoFDW7ga6OpVEy1YdChTtg/nO6tQB+gBjVc2ygImPnGoFdUVsmlr0+Y4c9ETMe
H9rQ6DUdNisWNkRbI7hQ5kgY0hve+sHaRu26XWj9LZtSrXkyjd+6vtzALX3EZWtS
tiumd9qPP7neIqljabM6jA5gusYntKmyNokbrwmZBMmhHbxmYxiFSXcieB3HxMBb
+emir7gRIV3sYp4V9q/LEEc=
-----END CERTIFICATE-----
`}
)

type mockCAServer struct {
	Certs []string
	Err   error
}

func (ca *mockCAServer) CreateCertificate(ctx context.Context, in *pb.IstioCertificateRequest) (*pb.IstioCertificateResponse, error) {
	if ca.Err == nil {
		return &pb.IstioCertificateResponse{CertChain: ca.Certs}, nil
	}
	return nil, ca.Err
}

func Test_writeStringArrToFile(t *testing.T) {
	type EI struct {
		strarr   []string
		filename string
	}
	testCases := map[string]struct {
		input       EI
		expectedErr string
	}{
		"Write to permitted file": {
			input:       EI{[]string{"abc", "123"}, "/tmp/file1"},
			expectedErr: "",
		},
		"No permission file": {
			input:       EI{[]string{"abc", "123"}, "/tmp/folder-does-not-exist/file1"},
			expectedErr: "open /tmp/folder-does-not-exist/file1: no such file or directory",
		},
	}

	for id, c := range testCases {
		err := writeStringArrToFile(c.input.strarr, c.input.filename)
		if err != nil && err.Error() != c.expectedErr {
			t.Errorf("Failed for %s. Expected error %s. Received error %s", id, c.expectedErr, err.Error())
		} else if err == nil && (len(c.expectedErr) > 0) {
			t.Errorf("Failed for %s. Expected error: %s, but writeStringArrToFile returned success", id, c.expectedErr)
		} else {
			t.Logf("Testcase %s successful.", id)
		}
	}

}

// This function tests both getToken and writeToFile
func Test_getToken(t *testing.T) {
	type EI struct {
		tokenfile  string
		tokenBytes []byte
	}
	type EO struct {
		token       string
		expectedErr string
	}

	testCases := map[string]struct {
		input      EI
		expectedOp EO
	}{
		"Valid tokenfile": {
			input:      EI{"/tmp/tokenfile", []byte("faketoken")},
			expectedOp: EO{"faketoken", ""},
		},
		"Non-existent tokenfile": {
			input:      EI{"/var/doesnt-exist", []byte("faketoken")},
			expectedOp: EO{"", ""}, //empty token returned
		},
	}
	for id, c := range testCases {
		// First create a file using writeToFile func.
		if id == "Valid tokenfile" {
			_ = writeToFile(c.input.tokenfile, c.input.tokenBytes)
		}
		// Now retrieve token
		token, err := getToken(c.input.tokenfile)
		if err != nil {
			if err.Error() != c.expectedOp.expectedErr {
				t.Errorf("%s: . Expected Error: %s, Received error: %s", id, c.expectedOp.expectedErr, err.Error())
			}
		} else {
			if token != c.expectedOp.token {
				t.Errorf("%s: Expected token: %s, Received token: %s", id, c.expectedOp.token, token)
			} else {
				t.Logf("%s: Successful!", id)
			}
		}
	}
}

func Test_getCertBytes(t *testing.T) {
	type EI struct {
		certfile     string
		certContents string
	}
	type EO struct {
		certbytes   []byte
		expectedErr string
	}

	testCases := map[string]struct {
		input      EI
		expectedOp EO
	}{
		"Valid certfile": {
			input:      EI{"/tmp/cert.pem", "fake-contents"},
			expectedOp: EO{[]byte("fake-contents"), ""},
		},
		"Certfile doesnot exist": {
			input:      EI{"/var/doesnt-exist.pem", "fake-contents"},
			expectedOp: EO{nil, "open /var/doesnt-exist.pem: no such file or directory"},
		},
	}
	for id, c := range testCases {
		// First create a file using writeToFile func.
		if id == "Valid certfile" {
			_ = writeToFile(c.input.certfile, []byte(c.input.certContents))
		}
		// Now retrieve cert contents
		cb, err := getCertBytes(c.input.certfile)
		if err != nil {
			if err.Error() != c.expectedOp.expectedErr {
				t.Errorf("%s: . Expected Error: %s, Received error: %s", id, c.expectedOp.expectedErr, err.Error())
			}
		} else {
			res := bytes.Compare(cb, c.expectedOp.certbytes)
			if res != 0 {
				t.Errorf("%s: Expected certificate contents: %s, Received contents: %s", id, string(c.expectedOp.certbytes), string(cb))
			} else {
				t.Logf("%s: Successful!", id)
			}
		}
	}
}

func Test_getCertFromCitadel(t *testing.T) {
	testCases := map[string]struct {
		server       mockCAServer
		expectedCert []string
		expectedErr  string
	}{
		"Valid certs": {
			server:       mockCAServer{Certs: fakeCert, Err: nil},
			expectedCert: fakeCert,
			expectedErr:  "",
		},
		"Error in response": {
			server:       mockCAServer{Certs: nil, Err: fmt.Errorf("test failure")},
			expectedCert: nil,
			expectedErr:  "rpc error: code = Unknown desc = test failure",
		},
		"Empty response": {
			server:       mockCAServer{Certs: []string{}, Err: nil},
			expectedCert: nil,
			expectedErr:  "invalid response cert chain",
		},
	}

	for id, tc := range testCases {
		// create a local grpc server
		s := grpc.NewServer()
		defer s.Stop()
		lis, err := net.Listen("tcp", mockServerAddress)
		if err != nil {
			t.Fatalf("Test case [%s]: failed to listen: %v", id, err)
		}

		// Create tokenfile
		_ = writeToFile(fakeTokenFile, []byte(fakeToken)) // tokenFile declared in certkey_handler.go
		go func() {
			pb.RegisterIstioCertificateServiceServer(s, &tc.server)
			if err := s.Serve(lis); err != nil {
				t.Logf("Test case [%s]: failed to serve: %v", id, err)
			}
		}()

		// The goroutine starting the server may not be ready, results in flakiness.
		time.Sleep(1 * time.Second)
		clientInfo := citadelClientInfo{
			CAAddress:         lis.Addr().String(),
			rootCertFile:      "",
			clusterID:         "",
			tokenFile:         fakeTokenFile,
			csrPEM:            []byte{01},
			certValidityInSec: 1,
			tls:               false,
		}
		resp, err := getCertFromCitadel(clientInfo)
		if err != nil {
			if err.Error() != tc.expectedErr {
				t.Errorf("Test case [%s]: error (%s) does not match expected error (%s)", id, err.Error(), tc.expectedErr)
			}
		} else {
			if tc.expectedErr != "" {
				t.Errorf("Test case [%s]: expect error: %s but got no error", id, tc.expectedErr)
			} else if !reflect.DeepEqual(resp, tc.expectedCert) {
				t.Errorf("Test case [%s]: resp: got %+v, expected %v", id, resp, tc.expectedCert)
			}
		}
	}
}

func Test_getCertKeyRotator(t *testing.T) {

	type EI struct {
		certInfo CertDetails
		caInfo   CADetails
	}
	testCases := map[string]struct {
		input       EI
		expectedErr string
	}{
		"Successful Cert Key Rotator": {
			input: EI{
				certInfo: CertDetails{
					RootCertFile:  "../tests/tls_conn_mgmt_certs/client-root-cert.pem",
					CertChainFile: "../tests/tls_conn_mgmt_certs/cert-chain.pem",
					CertFile:      "../tests/tls_conn_mgmt_certs/cert-chain.pem",
					KeyFile:       "../tests/tls_conn_mgmt_certs/key.pem",
					RSAKeySize:    2048,
					Org:           "Citrix Systems",
				},
				caInfo: CADetails{
					CAProvider:  "Istiod",
					ClusterID:   "Kubernetes",
					Env:         "onprem",
					TrustDomain: "cluster.local",
					NameSpace:   "fakenamespace",
					SAName:      "fakeserviceaccount",
					CertTTL:     1 * time.Second,
				},
			},
			expectedErr: "",
		},
	}
	err := os.MkdirAll(certDir, 0777)
	if err != nil {
		t.Errorf("Could not create directory /etc/certs")
	}

	for id, c := range testCases {
		s := grpc.NewServer()
		defer s.Stop()
		lis, err := net.Listen("tcp", mockServerAddress)
		if err != nil {
			t.Fatalf("Failed to listen: %v", err)
		}
		// Set CA Address
		c.input.caInfo.CAAddress = lis.Addr().String()
		err = setCertEnv(certDir, c.input.certInfo.RootCertFile, c.input.certInfo.CertChainFile, c.input.certInfo.CertFile, c.input.certInfo.KeyFile)
		if err != nil {
			t.Errorf("Could not create certificate environment. %s", err.Error())
		}

		certinfo := CertDetails{
			RootCertFile:  certDir + "/root-cert.pem",
			CertChainFile: certDir + "/cert-chain.pem",
			CertFile:      certDir + "/cert.pem",
			KeyFile:       certDir + "/key.pem",
			RSAKeySize:    2048,
			Org:           "Citrix Systems",
		}
		ckh, err := NewCertKeyHandler(&c.input.caInfo, &certinfo)

		if err != nil {
			t.Errorf("[ERROR] Could not create certkey handler. Error: %s", err.Error())
			continue
		}
		err = ckh.getCertKeyRotator()
		if err != nil && err.Error() != c.expectedErr {
			t.Errorf("%s: Expected error: %s, Received error: %s", id, c.expectedErr, err.Error())
		} else if err == nil {
			ckh.updateCertsAndKey()
			t.Logf("Success")
		} else {
			t.Logf("Success for %s. Expected and received error: %s", id, err.Error())
		}
		ckh.StopHandler()
	}
	if err := os.RemoveAll(certDir); err != nil {
		t.Errorf("Could not delete /etc/certs")
	}
}

func setCertEnv(certdir, rootcertpath, certchainpath, clientcertpath, keypath string) error {
	err := env.CopyFileContents(rootcertpath, certdir+"/root-cert.pem")
	if err != nil {
		return fmt.Errorf("Could not copy rootcert contents. Err=%s", err)
	}

	err = env.CopyFileContents(certchainpath, certdir+"/cert-chain.pem")
	if err != nil {
		return fmt.Errorf("Could not copy cert-chain contents. Err=%s", err)
	}

	err = env.CopyFileContents(clientcertpath, certdir+"/cert.pem")
	if err != nil {
		return fmt.Errorf("Could not copy client-cert contents. Err=%s", err)
	}

	err = env.CopyFileContents(keypath, certdir+"/key.pem")
	if err != nil {
		return fmt.Errorf("Could not copy key-file contents. Err=%s", err)
	}
	return nil
}

func Test_StartHandler(t *testing.T) {
	type EI struct {
		certInfo CertDetails
		caInfo   CADetails
		server   mockCAServer
	}
	testCases := map[string]struct {
		input       EI
		expectedErr string
	}{
		"Successful CertKey Handler": {
			input: EI{
				certInfo: CertDetails{
					RootCertFile:  "../tests/certkey_handler_certs/httpbin-root-cert.pem",
					CertChainFile: "../tests/certkey_handler_certs/httpbin-cert-chain.pem",
					CertFile:      "../tests/certkey_handler_certs/httpbin-cert-chain.pem",
					KeyFile:       "../tests/certkey_handler_certs/httpbin-key.pem",
					RSAKeySize:    2048,
					Org:           "Citrix Systems",
				},
				caInfo: CADetails{
					CAAddress:   "localhost:15002",
					CAProvider:  "Istiod",
					ClusterID:   "Kubernetes",
					Env:         "onprem",
					TrustDomain: "cluster.local",
					NameSpace:   "istio160-cpx",
					SAName:      "httpbin",
					CertTTL:     1 * time.Hour,
				},
				server: mockCAServer{Certs: validCert, Err: nil},
			},
			expectedErr: "",
		},
	}
	// 1. Create etc/certs directory
	err := os.MkdirAll(certDir, 0777)
	if err != nil {
		t.Errorf("Could not create directory /etc/certs")
	}

	for id, c := range testCases {
		s := grpc.NewServer()
		defer s.Stop()
		lis, err := net.Listen("tcp", c.input.caInfo.CAAddress)
		if err != nil {
			t.Fatalf("Failed to listen: %v", err)
		}
		// Set CA Address
		//c.input.caInfo.CAAddress = lis.Addr().String()
		// Create tokenfile
		_ = writeToFile(fakeTokenFile, []byte(fakeToken))
		go func() {
			pb.RegisterIstioCertificateServiceServer(s, &c.input.server)
			if err := s.Serve(lis); err != nil {
				t.Logf("Test case [%s]: failed to serve: %v", id, err)
			}
		}()
		// Copy input certs and key files to /etc/certs directory
		err = setCertEnv(certDir, c.input.certInfo.RootCertFile, c.input.certInfo.CertChainFile, c.input.certInfo.CertFile, c.input.certInfo.KeyFile)
		if err != nil {
			t.Errorf("Could not create certificate environment. %s", err.Error())
		}

		// The goroutine starting the server may not be ready, results in flakiness.
		time.Sleep(100 * time.Millisecond)
		certinfo := CertDetails{
			RootCertFile:  certDir + "/root-cert.pem",
			CertChainFile: certDir + "/cert-chain.pem",
			CertFile:      certDir + "/cert.pem",
			KeyFile:       certDir + "/key.pem",
			RSAKeySize:    2048,
			Org:           "Citrix Systems",
		}
		certkeyhdlr, err := NewCertKeyHandler(&c.input.caInfo, &certinfo)
		// Set below fields to ensure that citadelClient works fine
		certkeyhdlr.TokenFile = fakeTokenFile
		certkeyhdlr.tls = false

		ckhErrCh := make(chan error)
		go certkeyhdlr.StartHandler(ckhErrCh)
		for {
			select {
			case ckherr := <-ckhErrCh:
				if ckherr != nil {
					t.Logf("Certificate Key Handler returned with error. %s", ckherr.Error())
					certkeyhdlr.StopHandler()
					certkeyhdlr = nil
				}
			case <-time.After(3 * time.Second):
				t.Logf("3 seconds expired from the time of starting certificate key handler. Stop the handler")
				certkeyhdlr.StopHandler()
				certkeyhdlr = nil
			}
			break
		}
	}
	// Delete the etc/certs directory created in setCertEnv
	if err := os.RemoveAll(certDir); err != nil {
		t.Errorf("Could not delete /etc/certs")
	}
}
