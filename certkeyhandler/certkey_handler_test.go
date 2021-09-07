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
	// Retrieve validToken from /var/run/secrets/kubernetes.io/serviceaccount/token (firstPartyJWT) OR /var/run/secrets/tokens/istio-token file (thirdPartyJWT)
	validToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVneXJFUHFHZFFMYTRzNnIxdGttREFJTGRrejFVX2RKUS1Uc2RMdWFjNzQifQ.eyJhdWQiOlsiaXN0aW8tY2EiXSwiZXhwIjoxNjMwMDEzMjE4LCJpYXQiOjE2Mjk5NzAwMTgsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJodHRwYmluIiwicG9kIjp7Im5hbWUiOiJodHRwYmluLTc0ZmI2NjljYzYtZjR6dHEiLCJ1aWQiOiIxOWQ3ZWIzNC1hNDA1LTRkZmUtYWFiZC02OGViYjYxYzUzZDkifSwic2VydmljZWFjY291bnQiOnsibmFtZSI6Imh0dHBiaW4iLCJ1aWQiOiJhNmJhNzA5NS01ZDg3LTQzYTAtYjgxNC04NDdlZmQxNjA1OTUifX0sIm5iZiI6MTYyOTk3MDAxOCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50Omh0dHBiaW46aHR0cGJpbiJ9.jWCsgGf8hMsBXGpgAMVV4Cc27CpdAYiE-rR491ybaokUdRkPt5pACVRdKHQQTFjUKN8xHhcjmn8cix9sPzsSaduumicJFU7-3QZZ26uO4gfTMIyIlZBkCD9iDF6qP9L3fIjxF4dMW5hiJRsxT7T-5t1YTf8v7BT0N9NQdpeJ-AxyUo-FIrQ9y4jDiOjWBXyCtrsncH3TVN17QRLpkXu0rxwxOKn4f4qkHHfsgG7iYPe4w5bVO3Gr-WCKQU4Zo9m4vlxFUTO53xD490WgMzHzTKvYLjRYEdpAUVTiw_jqXxjRfuDGFgsH1cHeXaaQ9-kA-HFx1Y-FtbEG8oV0r3H9YwDG"
	// validCert is contents of httpbin-cert-chain.pem
	validCert = []string{`-----BEGIN CERTIFICATE-----
	MIIDQTCCAimgAwIBAgIRAOrWifkJuvLo13fbahzr/xYwDQYJKoZIhvcNAQELBQAw
	GDEWMBQGA1UEChMNY2x1c3Rlci5sb2NhbDAeFw0yMTA4MjYwOTI1MTVaFw0yMTEx
	MjQwOTI3MTVaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5vYW2
	0jJEV2n0Lx5jbXNnl0eDBI/YQPIUhtHoZtVAT6fp3LTqzhMLqEdbhnBLNlT7TO4Y
	lMrwyPa/yUPRJ2eVYMt+DEIoyd0AQUI6kno+p2DED4GXDoVXKqAGk42GkAJnajnn
	gmq5pn8ag3m+OL5QhXcRHaE+z2T5Mnq/HAQ2Wnmq41YjzqSSLAzMz4FRnb0KiaGF
	Cl0estdkIhDshlfaiA9TC/1IYZf3jy6swWKXQDn2g1mqDuRoc59I+MYLGaAvKbA/
	d00VBaHr8X0e0Q8NNc6GJGHD341kRML0pgw4YnR1gp/GW++m92LHCm092mZw2wWA
	3gF+vrypY3jgcHmlAgMBAAGjgZ0wgZowDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQW
	MBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaA
	FMhuZ3j3b54zo7MAcW6HP5T/pR0XMDoGA1UdEQEB/wQwMC6GLHNwaWZmZTovL2Ns
	dXN0ZXIubG9jYWwvbnMvaHR0cGJpbi9zYS9odHRwYmluMA0GCSqGSIb3DQEBCwUA
	A4IBAQCSC6lSTTvZcNlpdMv3XwN8Lx6VuF8xbrtp1XY6GF98Y/htFHtFZhAR8b8G
	kuFCg6b/yDz8d5rBidJ2wykIUVJT8MD99hkXj0H5pUqcP+GdyuwcjmHmuM2yzZZd
	VLk6xR22U4sWJnsUbB2KkX+JyDkFfzUfi63TvAUsCwhimLqYVyVPQu0TdaCLJz6v
	JcfWNMCpO/hFHFLWDaYF07bmEvdcTejTv1nNatK3y31cjSpTtDdBw9Yb3CkT6ugv
	BB3mqOR6ZGg8JsR88A53B0cVtXSYPs5xyjMg7LQmdc3aP+r9kPFJpCINSsOTixo2
	37+Fjk/yDnS97tGq49bUk84TchFM
	-----END CERTIFICATE-----
`,
		`-----BEGIN CERTIFICATE-----
	MIIC/TCCAeWgAwIBAgIRAK45nm1SGpEWfEwcBCTFPzEwDQYJKoZIhvcNAQELBQAw
	GDEWMBQGA1UEChMNY2x1c3Rlci5sb2NhbDAeFw0yMTA4MjAwOTQ4MTlaFw0zMTA4
	MTgwOTQ4MTlaMBgxFjAUBgNVBAoTDWNsdXN0ZXIubG9jYWwwggEiMA0GCSqGSIb3
	DQEBAQUAA4IBDwAwggEKAoIBAQCoCqDFPqaOkFpE22gnq3n3kgxfNbvvFLMEgV8y
	SdpqnfhFEPoBPW4c40zARTx96sqBqiwJfJV20KhVJGFPnAg53Q2Um69pk48r6C2I
	k+bfDo8alUVfAAHvkblOo4AjODYu5hCw2VVqkOaTyh5B6brfUcANu52Kdy8LOspa
	roSdBJEnFXTeAUJ8GUto6E8k+tQqhwbUiDWGJyBHQ898XWnP5CN2DAl/4aKOSEA6
	T5PMFv7Ms4g6Ima/UtjQWAqNX3VsSEMFELg6KLD3paNJV1cmr9JEd/5n9ig+kisR
	Wbcw2cjetcyVtGLF5IbzowqUpMVpjGeEvmo698L9Csm17NT5AgMBAAGjQjBAMA4G
	A1UdDwEB/wQEAwICBDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTIbmd492+e
	M6OzAHFuhz+U/6UdFzANBgkqhkiG9w0BAQsFAAOCAQEAiWav/f2y7fuRQsgtajgy
	we4OZyPbJ9dCIuMG1ufFF59HW6Xulpn3kUA7gl04a/nEohsnJaeMoqQz8mNCHSLs
	Arwi8rcVWFY4SKaW5ET6ZnApTP0jMzYFyvtWB8MGq4obOf8BQ+Sw3egiNekgnuis
	lExxnwEkcDxWcoK3f4Wn8Er+zjfTxeV5uxMpiJbcVho6v0mS8Dvt2QAnr6Yu7aGN
	LbgML+42IVRwqM9iqZT3biohUI5aXf+Hjk9Kz36i6fFHuo6FZ97SENE93Hp5gvPl
	KnwcLHQX+jMJV8R5zWRomA9wUckKFSfzZyYqcPkv5dHVIisV/i5X8pfNgHi/vWSR
	Tg==
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
					NameSpace:   "httpbin",
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
