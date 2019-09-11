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
	"citrix-istio-adaptor/nsconfigengine"
	"citrix-istio-adaptor/tests/env"
	"errors"
	"fmt"
	"github.com/chiradeep/go-nitro/config/ssl"
	"github.com/chiradeep/go-nitro/netscaler"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func getValueInt(obj map[string]interface{}, name string) (int, error) {
	if valI, ok := obj[name]; ok {
		if val, ok1 := valI.(int); ok1 {
			return val, nil
		}
		if val, ok1 := valI.(float64); ok1 {
			return int(val), nil
		}
		if val, ok1 := valI.(string); ok1 {
			valInt, err := strconv.Atoi(val)
			if err != nil {
				return 0, fmt.Errorf("Cannot convert value '%v' to integer - %v", val, err)
			}
			return valInt, nil
		}
		return 0, fmt.Errorf("value '%v' is of type %s and not int", valI, reflect.TypeOf(valI).String())
	}
	return 0, fmt.Errorf("key '%s' not found in resource", name)
}

func Test_fileExists(t *testing.T) {
	t.Logf("Test fileExists")
	if !fileExists("watcher.go") {
		t.Errorf("Failed as fileExists")
	}
	if fileExists("watcher_1.go") {
		t.Errorf("Failed as file does not Exist")
	}
}
func Test_addDir(t *testing.T) {
	t.Logf("Test addDirectory")
	cases := []struct {
		certName, keyName string
	}{
		{"../tests/certs/certrotation/app1.1000.rotationroot.com.crt", "../tests/certs/certrotation/app1.1000.rotationroot.com.key"},
		{"../tests/certs/certrotation/rootCA.crt", ""},
	}
	configAdaptor := new(configAdaptor)
	configAdaptor.client = env.GetNitroClient()
	w, err := newWatcher(configAdaptor)
	if err == nil {
		for _, c := range cases {
			err := w.addDir(c.certName, c.keyName)
			if err != nil {
				t.Errorf(" Exepected: File Added for watch successfully but got failed")
			}
			err = w.addDir(c.certName, c.keyName)
			if err != nil {
				t.Errorf("Expected False but got True while adding same cert and key")
			}
		}
	}
	err = w.addDir("/etc/file1/file.cert", "")
	if err != nil {
		er := errors.New("no such file or directory")
		if err.Error() != er.Error() {
			t.Errorf("Expected Err %v but got %v while trying to add non-existent directory for monitor", er, err)
		}
	}
}
func Test_run(t *testing.T) {
	configAdaptor := new(configAdaptor)
	configAdaptor.client = env.GetNitroClient()
	w, err := newWatcher(configAdaptor)
	if err := os.Mkdir("/tmp/adsclienttest", 0777); err != nil {
		t.Errorf("Could not create temp folder")
	}
	if err := os.Mkdir("/tmp/adsclienttest/.Test..", 0777); err != nil {
		t.Errorf("Could not create temp folder")
	}
	if err := env.CopyFileContents("../tests/certs/certrotation/app1.500.rotationroot.com.crt", "/tmp/adsclienttest/app1.500.rotationroot.com.crt"); err != nil {
		t.Errorf("Could not copy file. Error: %s", err.Error())
	}
	if err := env.CopyFileContents("../tests/certs/certrotation/app1.500.rotationroot.com.key", "/tmp/adsclienttest/app1.500.rotationroot.com.key"); err != nil {
		t.Errorf("Could not copy file. Error: %s", err.Error())
	}
	if err := env.CopyFileContents("../tests/certs/certrotation/rootCA.crt", "/tmp/adsclienttest/rootCA.crt"); err != nil {
		t.Errorf("Could not copy file. Error: %s", err.Error())
	}
	certPath := "/tmp/adsclienttest/app1.500.rotationroot.com.crt"
	keyPath := "/tmp/adsclienttest/app1.500.rotationroot.com.key"
	rootCertPath := "/tmp/adsclienttest/rootCA.crt"
	certName := nsconfigengine.GetSslCertkeyName(certPath)
	keyName := nsconfigengine.GetSslCertkeyName(keyPath) + "_key"
	rootCertName := nsconfigengine.GetSslCertkeyName(rootCertPath)
	t.Logf("Test UploadCert")
	err = nsconfigengine.UploadCert(configAdaptor.client, certPath, certName, keyPath, keyName)
	if err != nil {
		t.Errorf("Cert upload failed - %v", err)
	}
	err = nsconfigengine.UploadCert(configAdaptor.client, rootCertPath, rootCertName, "", "")
	if err != nil {
		t.Errorf(" Root Cert upload failed - %v", err)
	}
	t.Logf("Add certkey")
	_, err = configAdaptor.client.AddResource(netscaler.Sslcertkey.Type(), certName, ssl.Sslcertkey{Certkey: certName, Cert: "/nsconfig/ssl/" + certName, Key: "/nsconfig/ssl/" + keyName})
	if err != nil {
		t.Errorf("ssl certkey creation on NS failed - %v", err)
	}
	t.Logf("Add Root Certkey")
	_, err = configAdaptor.client.AddResource(netscaler.Sslcertkey.Type(), rootCertName, ssl.Sslcertkey{Certkey: rootCertName, Cert: "/nsconfig/ssl/" + rootCertName})

	certKey, errF := configAdaptor.client.FindResource(netscaler.Sslcertkey.Type(), certName)
	if errF != nil {
		t.Errorf("ssl certkey 'cert1' not found on netscaler")
	}
	daystoexpire1, errE1 := getValueInt(certKey, "daystoexpiration")
	if errE1 != nil {
		t.Errorf("Error fetching daystoexpiration - %v", errE1)
	}

	if err = env.CopyFileContents("../tests/certs/certrotation/app1.1000.rotationroot.com.crt", certPath); err != nil {
		t.Errorf("Could not copy file. Error: %s", err.Error())
	}
	if err = env.CopyFileContents("../tests/certs/certrotation/app1.1000.rotationroot.com.key", keyPath); err != nil {
		t.Errorf("Could not copy file. Error: %s", err.Error())
	}
	err = w.addDir(certPath, keyPath)
	err = w.addDir(rootCertPath, "")
	go w.Run()
	os.RemoveAll("/tmp/adsclienttest/.Test..")
	time.Sleep(2 * time.Second)
	certKey, errF = configAdaptor.client.FindResource(netscaler.Sslcertkey.Type(), certName)
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
	os.RemoveAll("/tmp/adsclienttest")
}
