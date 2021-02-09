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

func Test_UpdateBindings(t *testing.T) {
	oldCertFile := "../tests/tls_conn_mgmt_certs/cert-chain.pem"
	oldKeyFile := "../tests/tls_conn_mgmt_certs/key.pem"
	newCertFile := "../tests/certkey_handler_certs/sleep_cert_chain.pem"
	newKeyFile := "../tests/certkey_handler_certs/sleep_key.pem"
	client := env.GetNitroClient()
	certData, keyData, err := env.GetCertKeyData(oldCertFile, oldKeyFile)
	if err != nil {
		t.Errorf("Failed reading Cert/Key- %v", err)
	}
	nsOldCertFile := GetNSCompatibleNameHash(string([]byte(certData)), 55)
	nsOldKeyFile := GetNSCompatibleNameHash(string([]byte(keyData)), 55)
	UploadCertData(client, certData, nsOldCertFile, keyData, nsOldKeyFile)
	certData, keyData, err = env.GetCertKeyData(newCertFile, newKeyFile)
	if err != nil {
		t.Errorf("Failed reading Cert/Key- %v", err)
	}
	nsNewCertFile := GetNSCompatibleNameHash(string([]byte(certData)), 55)
	nsNewKeyFile := GetNSCompatibleNameHash(string([]byte(keyData)), 55)
	UploadCertData(client, certData, nsNewCertFile, keyData, nsNewKeyFile)
	lbObj := NewLBApi("lbent1s", "HTTP", "SSL", "ROUNDROBIN")
	lbObj.MaxConnections = 200
	lbObj.MaxHTTP2ConcurrentStreams = 300
	lbObj.MaxRequestsPerConnection = 50
	lbObj.LbMonitorObj = new(LBMonitor)
	lbObj.LbMonitorObj.Retries = 7
	lbObj.LbMonitorObj.Interval = 3
	lbObj.LbMonitorObj.IntervalUnits = "SEC"
	lbObj.LbMonitorObj.DownTime = 10
	lbObj.LbMonitorObj.DownTimeUnits = "SEC"
	lbObj.BackendTLS = []SSLSpec{{CertFilename: nsOldCertFile, PrivateKeyFilename: nsOldKeyFile, RootCertFilename: nsOldCertFile + "_ic1"}}
	err = lbObj.Add(client)
	if err != nil {
		t.Errorf("LBApi add failed with %v", err)
	}
	csObj := NewCSApi("cs2", "SSL", "2.2.1.1", 8443)
	csObj.AllowACL = false
	csObj.FrontendTLS = []SSLSpec{{CertFilename: nsOldCertFile, PrivateKeyFilename: nsOldKeyFile, RootCertFilename: nsOldCertFile + "_ic1", SNICert: false}}
	err = csObj.Add(client)
	if err != nil {
		t.Errorf("CSApi add failed with %v", err)
	}
	t.Logf("Test UpdateBindings")
	rootFile, err := UpdateBindings(client, nsOldCertFile, nsOldKeyFile, nsNewCertFile, nsNewKeyFile)
	if err != nil && rootFile != nsNewCertFile+"_ic1" {
		t.Errorf("UpdateBindings Failed as rootCertFile got =%v expected=%v", rootFile, nsNewCertFile+"_ic1")
	}
	t.Logf("Test CSApi Delete")
	err = csObj.Delete(client)
	if err != nil {
		t.Errorf("CSApi delete failed with %v", err)
	}
	t.Logf("Test LBApi delete")
	err = lbObj.Delete(client)
	if err != nil {
		t.Errorf("LBApi delete failed with %v", err)
	}
}

func Test_UpdateRootCABindings(t *testing.T) {
	oldRootCertFile := "../tests/tls_conn_mgmt_certs/root-cert.pem"
	newRootCertFile := "../tests/certs/certrotation/rootCA.crt"
	client := env.GetNitroClient()
	certData, _, err := env.GetCertKeyData(oldRootCertFile, "")
	if err != nil {
		t.Errorf("Failed reading RootCert- %v", err)
	}
	nsOldRootCertFile := GetNSCompatibleNameHash(string([]byte(certData)), 55)
	var keyData []byte
	UploadCertData(client, certData, nsOldRootCertFile, keyData, "")
	certData, _, err = env.GetCertKeyData(newRootCertFile, "")
	if err != nil {
		t.Errorf("Failed reading RootCert- %v", err)
	}
	nsNewRootCertFile := GetNSCompatibleNameHash(string([]byte(certData)), 55)
	UploadCertData(client, certData, nsNewRootCertFile, keyData, "")
	lbObj := NewLBApi("lbent1s", "HTTP", "SSL", "ROUNDROBIN")
	lbObj.MaxConnections = 200
	lbObj.MaxHTTP2ConcurrentStreams = 300
	lbObj.MaxRequestsPerConnection = 50
	lbObj.LbMonitorObj = new(LBMonitor)
	lbObj.LbMonitorObj.Retries = 7
	lbObj.LbMonitorObj.Interval = 3
	lbObj.LbMonitorObj.IntervalUnits = "SEC"
	lbObj.LbMonitorObj.DownTime = 10
	lbObj.LbMonitorObj.DownTimeUnits = "SEC"
	lbObj.BackendTLS = []SSLSpec{{CertFilename: "", PrivateKeyFilename: "", RootCertFilename: nsOldRootCertFile}}
	err = lbObj.Add(client)
	if err != nil {
		t.Errorf("LBApi add failed with %v", err)
	}
	csObj := NewCSApi("cs2", "SSL", "2.2.1.1", 8443)
	csObj.AllowACL = false
	csObj.FrontendTLS = []SSLSpec{{CertFilename: "", PrivateKeyFilename: "", RootCertFilename: nsOldRootCertFile, SNICert: false}}
	err = csObj.Add(client)
	if err != nil {
		t.Errorf("CSApi add failed with %v", err)
	}
	AddCertKey(client, nsNewRootCertFile, "")
	t.Logf("Test UpdateRootCABindings")
	UpdateRootCABindings(client, nsOldRootCertFile, nsNewRootCertFile)
	DeleteCertKey(client, nsOldRootCertFile)
	configs := []env.VerifyNitroConfig{
		{"lbvserver", "lbent1s", map[string]interface{}{"name": "lbent1s", "servicetype": "HTTP"}},
		{"servicegroup", "lbent1s", map[string]interface{}{"servicegroupname": "lbent1s", "servicetype": "SSL", "maxclient": 200, "maxreq": 50}},
		{"lbvserver_servicegroup_binding", "lbent1s", map[string]interface{}{"name": "lbent1s", "servicegroupname": "lbent1s"}},
		{"sslcertkey", nsNewRootCertFile, map[string]interface{}{"cert": "/nsconfig/ssl/" + nsNewRootCertFile, "certkey": nsNewRootCertFile}},
		{"sslservicegroup", "lbent1s", map[string]interface{}{"serverauth": "ENABLED", "servicegroupname": "lbent1s"}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Add %v, error %v", "lbent1s", err)
	}
	err = env.VerifyBindings(client, "sslservicegroup", "lbent1s", "sslcertkey", []map[string]interface{}{{"ca": true, "certkeyname": nsNewRootCertFile, "servicegroupname": "lbent1s"}})
	if err != nil {
		t.Errorf("Config verification failed for Add binding %v, error %v", "lbent1s", err)
	}
	configs = []env.VerifyNitroConfig{
		{"csvserver", "cs2", map[string]interface{}{"name": "cs2", "servicetype": "SSL", "ipv46": "2.2.1.1", "port": 8443}},
		{"sslcertkey", nsNewRootCertFile, map[string]interface{}{"cert": "/nsconfig/ssl/" + nsNewRootCertFile, "certkey": nsNewRootCertFile}},
		{"sslvserver", "cs2", map[string]interface{}{"clientauth": "DISABLED", "vservername": "cs2"}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Add cs2, error %v", err)
	}
	err = env.VerifyBindings(client, "sslvserver", "cs2", "sslcertkey", []map[string]interface{}{{"certkeyname": nsNewRootCertFile, "vservername": "cs2", "ca": true}})
	if err != nil {
		t.Errorf("Config verification failed for Add binding cs2, error %v", err)
	}
	t.Logf("Test CSApi Delete")
	err = csObj.Delete(client)
	if err != nil {
		t.Errorf("CSApi delete failed with %v", err)
	}
	t.Logf("Test LBApi delete")
	err = lbObj.Delete(client)
	if err != nil {
		t.Errorf("LBApi delete failed with %v", err)
	}
}
