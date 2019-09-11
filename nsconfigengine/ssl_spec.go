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

package nsconfigengine

import (
	"encoding/base64"
	"fmt"
	"github.com/chiradeep/go-nitro/config/lb"
	"github.com/chiradeep/go-nitro/config/ssl"
	"github.com/chiradeep/go-nitro/config/system"
	"github.com/chiradeep/go-nitro/netscaler"
	"io/ioutil"
	"log"
	"regexp"
	"strings"
)

const (
	sslCertPath        = "/nsconfig/ssl/"
	encodedSSLCertPath = "%2fnsconfig%2fssl"
)

// SSLSpec specifies the SSL certificates associated with a vserver/service on Citrix-ADC
type SSLSpec struct {
	SNICert            bool
	CertFilename       string
	PrivateKeyFilename string
	RootCertFilename   string
}

// GetSslCertkeyName returns a Citrix compatible certtkey name for a certificate
func GetSslCertkeyName(certPath string) string {
	re := regexp.MustCompile(`/([^/]*?)/([^/]+?)\..+$`)
	match := re.FindStringSubmatch(certPath)
	if len(match) > 2 {
		return GetNSCompatibleName(match[1] + "_" + match[2])
	}
	return GetNSCompatibleName(certPath)
}

func (sslObj *SSLSpec) addCert(client *netscaler.NitroClient, confErr *nitroError) (string, string) {
	entityCertName := ""
	rootCertName := ""
	if sslObj.CertFilename != "" {
		entityCertName = GetSslCertkeyName(sslObj.CertFilename)
		entityKeyName := GetSslCertkeyName(sslObj.PrivateKeyFilename) + "_key"
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslcertkey.Type(), entityCertName, ssl.Sslcertkey{Certkey: entityCertName, Cert: sslCertPath + entityCertName, Key: sslCertPath + entityKeyName}, "add"}, nil, nil))
	}
	if sslObj.RootCertFilename != "" {
		rootCertName = GetSslCertkeyName(sslObj.RootCertFilename)
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslcertkey.Type(), rootCertName, ssl.Sslcertkey{Certkey: rootCertName, Cert: sslCertPath + rootCertName}, "add"}, nil, nil))
	}
	return entityCertName, rootCertName
}

func addSSLServiceGroup(client *netscaler.NitroClient, serviceGroupName string, sslObjs []SSLSpec, confErr *nitroError) {
	serverAuth := "DISABLED"
	for _, sslObj := range sslObjs {
		entityCertName, rootCertName := sslObj.addCert(client, confErr)
		if entityCertName != "" {
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslservicegroup_sslcertkey_binding.Type(), serviceGroupName, ssl.Sslservicegroupsslcertkeybinding{Servicegroupname: serviceGroupName, Certkeyname: entityCertName}, "add"}, nil, nil))
		}
		if rootCertName != "" {
			serverAuth = "ENABLED"
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslservicegroup_sslcertkey_binding.Type(), serviceGroupName, ssl.Sslservicegroupsslcertkeybinding{Servicegroupname: serviceGroupName, Certkeyname: rootCertName, Ca: true}, "add"}, nil, nil))
		}
	}
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslservicegroup.Type(), serviceGroupName, ssl.Sslservicegroup{Servicegroupname: serviceGroupName, Serverauth: serverAuth}, "add"}, nil, nil))
}

func addSSLVserver(client *netscaler.NitroClient, vserverName string, sslObjs []SSLSpec, SSLClientAuth bool, confErr *nitroError) {
	sniEnable := "DISABLED"
	for _, sslObj := range sslObjs {
		entityCertName, rootCertName := sslObj.addCert(client, confErr)
		if entityCertName != "" {
			if sslObj.SNICert == true {
				sniEnable = "ENABLED"
			}
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslvserver_sslcertkey_binding.Type(), vserverName, ssl.Sslvserversslcertkeybinding{Vservername: vserverName, Certkeyname: entityCertName, Snicert: sslObj.SNICert}, "add"}, nil, nil))
		}
		if rootCertName != "" {
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslvserver_sslcertkey_binding.Type(), vserverName, ssl.Sslvserversslcertkeybinding{Vservername: vserverName, Certkeyname: rootCertName, Ca: true}, "add"}, nil, nil))
		}
	}
	sslClientAuthVal := "DISABLED"
	if SSLClientAuth == true {
		sslClientAuthVal = "ENABLED"
	}
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslvserver.Type(), vserverName, ssl.Sslvserver{Vservername: vserverName, Snienable: sniEnable, Clientauth: sslClientAuthVal}, "set"}, nil, nil))

}

// UploadCert upload a certificate and key on to the Citrix-ADC
func UploadCert(client *netscaler.NitroClient, certPath, certNsFileName, keyPath, keyNsFileName string) error {
	confErr := newNitroError()
	data, err := ioutil.ReadFile(certPath)
	if err != nil {
		log.Println("[ERROR] Reading File", certPath, err)
		return err
	}
	str := base64.StdEncoding.EncodeToString(data)
	log.Println("[DEBUG] NetScaler Transfer", certPath, certNsFileName)
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Systemfile.Type(), certNsFileName, system.Systemfile{Fileencoding: "BASE64", Filelocation: sslCertPath, Filecontent: str, Filename: certNsFileName}, "add"}, nil, nil))
	if keyPath != "" {
		data, err := ioutil.ReadFile(keyPath)
		if err != nil {
			log.Println("[ERROR] Reading File:", keyPath, err)
			return err
		}
		str := base64.StdEncoding.EncodeToString(data)
		log.Println("[DEBUG] NetScaler Transfer", keyPath, keyNsFileName)
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Systemfile.Type(), keyNsFileName, system.Systemfile{Fileencoding: "BASE64", Filelocation: sslCertPath, Filecontent: str, Filename: keyNsFileName}, "add"}, nil, nil))
	}
	return confErr.getError()
}

// DeleteCert deleted a certificate/key from the Citrix-ADC
func DeleteCert(client *netscaler.NitroClient, fileName string) error {
	return client.DeleteResourceWithArgsMap(netscaler.Systemfile.Type(), fileName, map[string]string{"filelocation": encodedSSLCertPath})
}

// UpdateCert updates the ssl certkey on the Citrix-ADC
func UpdateCert(client *netscaler.NitroClient, certKeyName, certFileName, keyFileName string) error {
	sslCertKey := ssl.Sslcertkey{Certkey: certKeyName, Cert: certFileName}
	if keyFileName != "" {
		sslCertKey.Key = keyFileName
	}
	return doNitro(client, nitroConfig{netscaler.Sslcertkey.Type(), certKeyName, sslCertKey, "update"}, nil, nil)
}

// SSLForwardSpec specifies a set of domains to forwards https traffic to
type SSLForwardSpec struct {
	LbVserverName string
	SNINames      []string
}

func getPolicyRuleForSNINames(serverNames []string) string {
	serverNameValue := "("
	for serverID, serverName := range serverNames {
		if serverID != 0 {
			serverNameValue = serverNameValue + " || "
		}
		if strings.Contains(serverName, "*") {
			serverNameValue = serverNameValue + "CLIENT.SSL.CLIENT_HELLO.SNI.REGEX_MATCH(re/" + strings.Replace(serverName, "*", ".*", -1) + "/)"
		} else {
			serverNameValue = serverNameValue + "CLIENT.SSL.CLIENT_HELLO.SNI.CONTAINS(\"" + serverName + "\")"
		}
	}
	serverNameValue = serverNameValue + ")"
	return serverNameValue
}

func addSSLForwardSpec(client *netscaler.NitroClient, vserverName string, forwardObjs []SSLForwardSpec, confErr *nitroError) {
	log.Printf("[TRACE] SSLForwardSpec add: %v", forwardObjs)
	var bPolicyName string
	var priority int

	for index, forwardObj := range forwardObjs {
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Lbvserver.Type(), forwardObj.LbVserverName, lb.Lbvserver{Name: forwardObj.LbVserverName, Servicetype: "TCP"}, "add"}, nil, nil))
		priority := index + 1
		sslPolicyName := vserverName + "_ssl_" + fmt.Sprint(priority)
		sslActionName := vserverName + "_ssl_" + forwardObj.LbVserverName
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslaction.Type(), sslActionName, ssl.Sslaction{Name: sslActionName, Forward: forwardObj.LbVserverName}, "add"}, []string{"set command not present for this resource"}, nil))
		rule := getPolicyRuleForSNINames(forwardObj.SNINames)
		policyObj, errp := client.FindResource(netscaler.Sslpolicy.Type(), sslPolicyName)
		if errp == nil {
			curActionName, _ := getValueString(policyObj, "action")
			curRule, _ := getValueString(policyObj, "rule")
			if curActionName != sslActionName || curRule != rule {
				confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslvserver_sslpolicy_binding.Type(), vserverName, map[string]string{"vservername": vserverName, "policyname": sslPolicyName, "type": "CLIENTHELLO_REQ"}, "delete"}, nil, nil))
			}
		}
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslpolicy.Type(), sslPolicyName, ssl.Sslpolicy{Name: sslPolicyName, Rule: rule, Action: sslActionName}, "add"}, nil, nil))
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslvserver_sslpolicy_binding.Type(), vserverName, ssl.Sslvserversslpolicybinding{Vservername: vserverName, Policyname: sslPolicyName, Priority: priority, Type: "CLIENTHELLO_REQ"}, "add"}, nil, nil))
	}
	/* Delete stale bindings*/
	sslvserverSslpolicyBindings, err := client.FindResourceArray(netscaler.Sslvserver_sslpolicy_binding.Type(), vserverName)
	if err != nil {
		return
	}
	for _, binding := range sslvserverSslpolicyBindings {
		if bPolicyName, err = getValueString(binding, "policyname"); err != nil {
			continue
		}
		if priority, err = getValueInt(binding, "priority"); err != nil {
			continue
		}
		if priority <= len(forwardObjs) {
			continue
		}
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslvserver_sslpolicy_binding.Type(), vserverName, map[string]string{"vservername": vserverName, "policyname": bPolicyName, "type": "CLIENTHELLO_REQ"}, "delete"}, nil, nil))
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslpolicy.Type(), bPolicyName, nil, "delete"}, nil, nil))
	}
	/* Delete stale sslaction */
	sslActions, errs := client.FindFilteredResourceArray(netscaler.Sslaction.Type(), map[string]string{"referencecount": "0"})
	if errs != nil {
		return
	}
	for _, sslAction := range sslActions {
		var actionName string
		if actionName, err = getValueString(sslAction, "name"); err == nil {
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslaction.Type(), actionName, nil, "delete"}, nil, nil))
		}
	}
}
