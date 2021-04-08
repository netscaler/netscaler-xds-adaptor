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
	// Retrieve validToken from /var/run/secrets/kubernetes.io/serviceaccount/token file
	validToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjJjN3ZveFFUS0ZRckZrWF91TDJUU0t6TG1NanBrUnNCN3RZYzlIT2NFWWMifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJteW5hbWVzcGFjZSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJodHRwYmluLXRva2VuLXo4NWprIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6Imh0dHBiaW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiI2ZDVlMGNmNC1jODQ4LTQyMmUtODRjNS0zOGVkZjEyYmQ4NDMiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6bXluYW1lc3BhY2U6aHR0cGJpbiJ9.rIA3k5b_kAAwa-Z-sDKJ92K_h98ynNC-dvYpYTUbauz0iITScV3WikKdFz7sWMV0T8XhofThSSyFYULsqAz_3P3w3jzOYIXxFBfRXOWCCAh5NYHcXmLU0V22dAPI6Ilhun2YWr0GmqXgQsbF0Bf_b4ieQSRRU6FYIKxtVwdAmVOTFgnAcIBETY1yIvVLbgLVyCjKUtp7WF6oHCM6F0IPZmMREiWQN8xco0M6hrfCLMUflSXZLdIpZq_BYfwVbQ_W29TewOAOjbCC9JIfSG1NRljk25BZmlqlB-t8AqylgYvp_ELlaBSYBKXcqs8JK6cxOdQwvNvCQ0i5a-CZtx4mUA"
	validCert  = []string{`-----BEGIN CERTIFICATE-----
	MIIDITCCAgmgAwIBAgIQMputO4QfiMx3hxwuVW0VlTANBgkqhkiG9w0BAQsFADAY
	MRYwFAYDVQQKEw1jbHVzdGVyLmxvY2FsMB4XDTIxMDEyODExMDUwNFoXDTIxMDQy
	ODExMDUwNFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL7ob6fS
	BZNdY2HR43va1ODv63xdnkKhmfNo/8BzOXxC9VKlObkc1kQVRJgslLYqubFDVHWO
	cWN2ZK0nzu/PBGqyVfGhWkZLRzNSVRn5gTdIVZBO5winbEUciN5+RV0sfJWRYYtM
	sKPV1qOu8j8eN7g3QV0gwNU91tXVbOlavIRG9ODeLlMC4p7A1UX9HI5IdLvqbGR/
	z8CyGwBPwDQRw4O6/AdtgYph/2jHaUPscxCgVQzOtzPhn/Bk1oqkXSBnPOO0Cz1o
	w7Vp1QwrxgX0ifUC1MGuX8B8x9NkSK86UhqfOjR56+iwWN+VUR/yjMjEgabmy8Bs
	QEX8GKX/RnafIdECAwEAAaN/MH0wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQG
	CCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMD4GA1UdEQEB/wQ0MDKG
	MHNwaWZmZTovL2NsdXN0ZXIubG9jYWwvbnMvbXluYW1lc3BhY2Uvc2EvaHR0cGJp
	bjANBgkqhkiG9w0BAQsFAAOCAQEAawCF5qjwfkIx293H48Q82S5Jqh1dXs1rjlnm
	5PKj9GUimV+nuA6hM48ZryvPR5TDXUlZnkpzCXfO+3u5yVsdd2x4Tag5JV1VY5Ve
	/czF1T00hTtaaM5pYe6ZebCGnuBuImEP3HIWGkRvv9SkDjrOGWkGEcHGVyIiCvPw
	zsuqnnSMvMzClqK6H2sFOLze/Tv6HCLW7RzlQi6TJKkCJ0+thiwarQENox9rDqtL
	i/BY+guBbql6oQ4s5qDCO9SpgcuYlDjLKb8OZyAR895BBy8Z9MyY6A8OOH/17VuC
	WqicAxp2BrK8UwCmhhjujDq/MVtR+ytIWAERHf+gSy7QjLw97g==
	-----END CERTIFICATE-----
`,
		`-----BEGIN CERTIFICATE-----
	MIIC3TCCAcWgAwIBAgIQFYX2eTXCz7OhCsoVGeRjIzANBgkqhkiG9w0BAQsFADAY
	MRYwFAYDVQQKEw1jbHVzdGVyLmxvY2FsMB4XDTIwMTIyMTExNTc1MVoXDTMwMTIx
	OTExNTc1MVowGDEWMBQGA1UEChMNY2x1c3Rlci5sb2NhbDCCASIwDQYJKoZIhvcN
	AQEBBQADggEPADCCAQoCggEBAK2cfQ5SmnQPU/c3lD/dz6pfjHXvCnipasQSmMCu
	GdUReC68VMqKzBAYKNqzrgC25U3StFggx2IR86M5MPmthZAX6wVklfYhO0xhz3hF
	ucuR8gRlLymlrccWwdft2o6npPgWV+EJynORbJzh/EkKbb9k5ZZTrrkHlD/nCg2H
	VhjpPjqaA3hOiv3BoqtGiYrbVWL1b+HEzLqh7mnB7+YL7SIvJ8zPzj1sgZu1aFab
	F5xyjf0VPztHaNCyOizF6qcRWcxJfxhOjn6j4HKCBl1AYNssu+P3QQYNlX6F+EtI
	BdaHuPf+a4iN8aAX6PAka93kumtJH0PAqdUSAcuX21rfp/UCAwEAAaMjMCEwDgYD
	VR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
	ADzx0FVsc18ty8NK/1FWg6SNc66z+gjs5pr9rFtTQaWjzIaLlEEVM5K2IM2fb96r
	AS7/z3n6gDwr2AcUNaHJzyYVdFmLVAO6dSYsKKMMIyIGUbiMV4R8mmFpgO/lkRE0
	Hn7KGBNd5sQYEascpO3Z+50aqgYl//CQRj0crBreRJDUiup2D9lkBkMtBAyx8D7I
	BQPPBOTKybPtjiyfON4hDmxJ36rp0DIcXUqtRtCLe0R+yP0Vx9mROVlpuMZDPIaF
	nbnFXrwvtAVM4z6WOFsEWBEJXrIHNA30fx8n5jy+6n9zU31h6qkbtoc4CQlunCx2
	BAi6I+w9PCup8pTzaAH5mbs=
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
					RootCertFile:  "../tests/tls_conn_mgmt_certs/root-cert.pem",
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
		err = env.SetCertEnv(certDir, c.input.certInfo.RootCertFile, c.input.certInfo.CertChainFile, c.input.certInfo.CertFile, c.input.certInfo.KeyFile)
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
		token    string
	}
	testCases := map[string]struct {
		input       EI
		expectedErr string
	}{
		"Successful CertKey Handler": {
			input: EI{
				certInfo: CertDetails{
					RootCertFile: "../tests/certkey_handler_certs/httpbin-root-cert.pem",
					RSAKeySize:   2048,
					Org:          "Citrix Systems",
				},
				caInfo: CADetails{
					CAAddress:   "localhost:15002",
					CAProvider:  "Istiod",
					ClusterID:   "Kubernetes",
					Env:         "onprem",
					TrustDomain: "cluster.local",
					NameSpace:   "mynamespace",
					SAName:      "httpbin",
					CertTTL:     2160 * time.Hour,
				},
				server: mockCAServer{Certs: validCert, Err: nil},
				token:  validToken,
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
		_ = writeToFile(fakeTokenFile, []byte(c.input.token))
		go func() {
			pb.RegisterIstioCertificateServiceServer(s, &c.input.server)
			if err := s.Serve(lis); err != nil {
				t.Logf("Test case [%s]: failed to serve: %v", id, err)
			}
		}()
		// Copy input certs and key files to /etc/certs directory
		err = env.CopyFileContents(c.input.certInfo.RootCertFile, certDir+"/root-cert.pem")
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
		certkeyhdlr.TokenFile = validToken
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
		t.Errorf("Could not delete %s", certDir)
	}
}
