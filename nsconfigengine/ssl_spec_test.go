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

package nsconfigengine

import (
	"citrix-xds-adaptor/tests/env"
	"testing"

	"github.com/chiradeep/go-nitro/config/ssl"
	"github.com/chiradeep/go-nitro/netscaler"
)

func Test_GetSslCertkeyName(t *testing.T) {
	cases := []struct {
		input          string
		expectedOutput string
	}{
		{"/etc/certs/tls.crt", "certs_tls"},
		{"/etc/certs/application-a-certs/tls.crt", "application_a_certs_tls"},
		{"/etc/certs/ingressgateway-certs/tls.crt", "ingressgateway_certs_tls"},
		{"dummy", "dummy"},
	}

	for _, c := range cases {
		if output := GetSslCertkeyName(c.input); output != c.expectedOutput {
			t.Errorf("incorrect output for `%s` : expected `%s` but got `%s`", c.input, c.expectedOutput, output)
		}
	}
}

func Test_certOperations(t *testing.T) {
	client := env.GetNitroClient()
	t.Logf("Test UploadCert")
	err := UploadCert(client, "../tests/certs/certrotation/app1.500.rotationroot.com.crt", "app1.rotationroot.com.crt", "../tests/certs/certrotation/app1.500.rotationroot.com.key", "app1.rotationroot.com.key")
	if err != nil {
		t.Errorf("Cert upload failed - %v", err)
	}
	t.Logf("Add certkey")
	err = doNitro(client, nitroConfig{netscaler.Sslcertkey.Type(), "cert1", ssl.Sslcertkey{Certkey: "cert1", Cert: "app1.rotationroot.com.crt", Key: "app1.rotationroot.com.key"}, "add"}, nil, nil)
	if err != nil {
		t.Errorf("ssl certkey creation on NS failed - %v", err)
	}
	certKey, errF := client.FindResource(netscaler.Sslcertkey.Type(), "cert1")
	if errF != nil {
		t.Errorf("ssl certkey 'cert1' not found on netscaler")
	}
	daystoexpire1, errE1 := getValueInt(certKey, "daystoexpiration")
	if errE1 != nil {
		t.Errorf("Error fetching daystoexpiration - %v", errE1)
	}
	t.Logf("Test DeleteCert")
	err = DeleteCert(client, "app1.rotationroot.com.crt")
	if err != nil {
		t.Errorf("Error deleting certfile - %v", err)
	}
	err = DeleteCert(client, "app1.rotationroot.com.key")
	if err != nil {
		t.Errorf("Error deleting keyfile - %v", err)
	}
	t.Logf("Upload new cert files")
	err = UploadCert(client, "../tests/certs/certrotation/app1.1000.rotationroot.com.crt", "app1.rotationroot.com.crt", "../tests/certs/certrotation/app1.1000.rotationroot.com.key", "app1.rotationroot.com.key")
	if err != nil {
		t.Errorf("Cert upload failed - %v", err)
	}
	t.Logf("Test UpdateCert")
	err = UpdateCert(client, "cert1", "app1.rotationroot.com.crt", "app1.rotationroot.com.key")
	if err != nil {
		t.Errorf("Cert update failed - %v", err)
	}
	certKey, errF = client.FindResource(netscaler.Sslcertkey.Type(), "cert1")
	if errF != nil {
		t.Errorf("ssl certkey 'cert1' not found on netscaler")
	}
	daystoexpire2, errE2 := getValueInt(certKey, "daystoexpiration")
	if errE2 != nil {
		t.Errorf("Error fetching daystoexpiration - %v", errE2)
	}
	if daystoexpire1 == daystoexpire2 {
		t.Errorf("Certificate not updated correctly. DaysToExpire remains same - %d", daystoexpire2)
	}
}
