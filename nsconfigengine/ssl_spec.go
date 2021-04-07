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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/chiradeep/go-nitro/config/lb"
	"github.com/chiradeep/go-nitro/config/ssl"
	"github.com/chiradeep/go-nitro/config/system"
	"github.com/chiradeep/go-nitro/netscaler"
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
	Cert               string
	PrivateKey         string
	RootCert           string
}

//SSLVserverBinding specifies the SSL Vservername and SNI details needed for cetkey binding to ssl vserver during cert rotation
type SSLVserverBinding struct {
	vserverName string
	sniCert     bool
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

func unbindBindSSLCertKeyBindings(client *netscaler.NitroClient, certKeyName, resourceName, entityName, entityType, operation string, isCA bool) {
	confErr := newNitroError()
	confErr.updateError(doNitro(client, nitroConfig{entityType, entityName, map[string]string{resourceName: entityName, "Certkeyname": certKeyName, "Ca": strconv.FormatBool(isCA)}, operation}, nil, nil))
}

// UpdateBindings will unbind bindings of oldCertKeyName from SSL Vserver/ServiceGroup and bind with newCertKeyName
func UpdateBindings(client *netscaler.NitroClient, oldCertKeyName, oldKeyFileName, newCertKeyName, newKeyFileName string) (string, error) {
	var vserverNames, serviceNames []string
	var vserverBinds []SSLVserverBinding
	var vserverBind SSLVserverBinding
	var CA = false
	certChain, err := GetCertChain(client, oldCertKeyName)
	if err != nil {
		return "", err
	}
	if err == nil && len(certChain) >= 1 {
		CA = true
	}

	vserverBindings, err := client.FindResourceArray(netscaler.Sslcertkey_sslvserver_binding.Type(), oldCertKeyName)
	if err == nil {
		for _, vserverBinding := range vserverBindings {
			if vserverName, err := getValueString(vserverBinding, "servername"); err == nil {
				bindings, _ := client.FindResourceArray(netscaler.Sslvserver_sslcertkey_binding.Type(), vserverName)
				unbindBindSSLCertKeyBindings(client, oldCertKeyName, "Vservername", vserverName, netscaler.Sslvserver_sslcertkey_binding.Type(), "delete", false)
				vserverBind.vserverName = vserverName
				vserverBind.sniCert = false
				for _, binding := range bindings {
					if certName, err := getValueString(binding, "certkey"); err == nil {
						if certName == oldCertKeyName {
							{
								if binding["snicert"] != nil {
									vserverBind.sniCert = binding["snicert"].(bool)
								}
							}
						}
					}
				}
				vserverNames = append(vserverNames, vserverName)
				vserverBinds = append(vserverBinds, vserverBind)
				if CA == true {
					unbindBindSSLCertKeyBindings(client, certChain[len(certChain)-1], "Vservername", vserverName, netscaler.Sslvserver_sslcertkey_binding.Type(), "delete", true)
				}
			}
		}
	}
	serviceBindings, err := client.FindResourceArray(netscaler.Sslcertkey_service_binding.Type(), oldCertKeyName)
	if err == nil {
		for _, serviceBinding := range serviceBindings {
			if serviceName, err := getValueString(serviceBinding, "servicename"); err == nil {
				unbindBindSSLCertKeyBindings(client, oldCertKeyName, "Servicegroupname", serviceName, netscaler.Sslservicegroup_sslcertkey_binding.Type(), "delete", false)
				serviceNames = append(serviceNames, serviceName)
				if CA == true {
					unbindBindSSLCertKeyBindings(client, certChain[len(certChain)-1], "Servicegroupname", serviceName, netscaler.Sslservicegroup_sslcertkey_binding.Type(), "delete", true)
				}
			}
		}
	}
	DeleteCertKey(client, oldCertKeyName)
	deleteCertIntFile(client, certChain)
	AddCertKey(client, newCertKeyName, newKeyFileName)
	bindSSLVserver(client, newCertKeyName, vserverBinds) // Separate function is written to add SNI Details as well
	var vName []string
	bindSSLCertKeySSLVserverServiceGroup(client, newCertKeyName, vName, serviceNames, false)
	if len(certChain) >= 1 {
		newCertChain, err := GetCertChain(client, newCertKeyName)
		if err == nil && len(newCertChain) >= 1 {
			bindSSLCertKeySSLVserverServiceGroup(client, newCertChain[len(newCertChain)-1], vserverNames, serviceNames, true)
			return newCertChain[len(newCertChain)-1], nil
		}
	}
	return "", err
}

//UpdateRootCABindings will unbind oldRootCertFile from vserver/serviecgroup and bind with newcertkeynam
func UpdateRootCABindings(client *netscaler.NitroClient, oldRootFileName, newRootFileName string) {
	vserverBindings, err := client.FindResourceArray(netscaler.Sslcertkey_sslvserver_binding.Type(), oldRootFileName)
	if err == nil {
		for _, vserverBinding := range vserverBindings {
			if vserverName, err := getValueString(vserverBinding, "servername"); err == nil {
				unbindBindSSLCertKeyBindings(client, oldRootFileName, "vservername", vserverName, netscaler.Sslvserver_sslcertkey_binding.Type(), "delete", true)
				unbindBindSSLCertKeyBindings(client, newRootFileName, "vservername", vserverName, netscaler.Sslvserver_sslcertkey_binding.Type(), "add", true)
			}
		}
	}
	serviceBindings, err := client.FindResourceArray(netscaler.Sslcertkey_service_binding.Type(), oldRootFileName)
	if err == nil {
		for _, serviceBinding := range serviceBindings {
			if serviceName, err := getValueString(serviceBinding, "servicename"); err == nil {
				unbindBindSSLCertKeyBindings(client, oldRootFileName, "servicegroupname", serviceName, netscaler.Sslservicegroup_sslcertkey_binding.Type(), "delete", true)
				unbindBindSSLCertKeyBindings(client, newRootFileName, "servicegroupname", serviceName, netscaler.Sslservicegroup_sslcertkey_binding.Type(), "add", true)
			}
		}
	}
}

func deleteCertIntFile(client *netscaler.NitroClient, certChain []string) {
	for _, file := range certChain {
		DeleteCertKey(client, file)
	}
}
func bindSSLCertKeySSLVserverServiceGroup(client *netscaler.NitroClient, certKeyName string, vserverBindings, serviceBindings []string, isCA bool) {
	for _, vserverName := range vserverBindings {
		unbindBindSSLCertKeyBindings(client, certKeyName, "Vservername", vserverName, netscaler.Sslvserver_sslcertkey_binding.Type(), "add", isCA)
	}
	for _, serviceName := range serviceBindings {
		unbindBindSSLCertKeyBindings(client, certKeyName, "Servicegroupname", serviceName, netscaler.Sslservicegroup_sslcertkey_binding.Type(), "add", isCA)
	}

}

func bindSSLVserver(client *netscaler.NitroClient, certKeyName string, vserverBinds []SSLVserverBinding) {
	confErr := newNitroError()
	for _, vserverBind := range vserverBinds {
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslvserver_sslcertkey_binding.Type(), vserverBind.vserverName, ssl.Sslvserversslcertkeybinding{Vservername: vserverBind.vserverName, Certkeyname: certKeyName, Snicert: vserverBind.sniCert}, "add"}, nil, nil))
	}
}

//DeleteCertKey will delete ssl cert from ADC and also remove the certificate and key file
func DeleteCertKey(client *netscaler.NitroClient, certKeyName string) {
	entityType := netscaler.Sslcertkey.Type()
	cert, err := client.FindResource(entityType, certKeyName)
	if err == nil {
		//Delete Intermediate Certificates and files if present
		//deleteIntermediateCertificates(client, certKeyName)
		err := client.DeleteResource(netscaler.Sslcertkey.Type(), certKeyName)
		if err == nil {
			DeleteCert(client, certKeyName)
			/* If is is Private Cert, try to remove key, For that as Key will be stored as
			/nsconfig/ssl/d76ee765eb2d454e0795425f680ac28f get lastIndex for KeyFile name */
			if keyName, err := getValueString(cert, "key"); err == nil {
				keyFileName := keyName[strings.LastIndex(keyName, "/")+1:]
				DeleteCert(client, keyFileName)
			}
		}
	}
}
func isCertBindingPresent(client *netscaler.NitroClient, entityName, entityCertName, entityType string) bool {
	certBindings, err := client.FindResourceArray(entityType, entityName)
	if err == nil {
		for _, certBinding := range certBindings {
			if certKey, err := getValueString(certBinding, "certkeyname"); err == nil {
				if certKey == entityCertName {
					return true
				}
			}
		}
	}
	return false
}

// IsCertKeyPresent will check if certKey already added in Citrix ADC
func IsCertKeyPresent(client *netscaler.NitroClient, certKeyName, keyFileName string) bool {
	cert, err := client.FindResource(netscaler.Sslcertkey.Type(), certKeyName)
	if err == nil {
		if keyName, err := getValueString(cert, "key"); err == nil {
			name := keyName[strings.LastIndex(keyName, "/")+1:]
			if keyFileName == name {
				return true
			}
		}
	}
	return false
}

// AddCertKey will add Certkey and bundle option will be set true for non CA certificate
func AddCertKey(client *netscaler.NitroClient, certKeyName, keyFileName string) {
	confErr := newNitroError()
	if keyFileName != "" {
		if IsCertKeyPresent(client, certKeyName, keyFileName) == false {
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslcertkey.Type(), certKeyName, ssl.Sslcertkey{Certkey: certKeyName, Cert: sslCertPath + certKeyName, Key: sslCertPath + keyFileName, Bundle: "Yes"}, "add"}, nil, nil))
		}
	} else {
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslcertkey.Type(), certKeyName, ssl.Sslcertkey{Certkey: certKeyName, Cert: sslCertPath + certKeyName}, "add"}, nil, nil))
	}
}

//GetCertChain will give the list of the linked Certificate for given CertKey
func GetCertChain(client *netscaler.NitroClient, certKeyName string) ([]string, error) {
	chains, err := client.FindResource("sslcertificatechain", certKeyName)
	var certChain []string
	if err != nil {
		log.Printf("[ERROR] %v getting sslcertificatechain for %v", err, certKeyName)
		return certChain, err
	}
	if chains != nil {
		if chains["chainlinked"] == nil {
			return certChain, err
		}
		for _, v := range chains["chainlinked"].([]interface{}) {
			str := v.(string)
			certChain = append(certChain, str)
		}
	}
	return certChain, nil
}

// addInlineCert will add certificate/key, CAcert for the case where certs are provided as inline string
func (sslObj *SSLSpec) addInlineCert(client *netscaler.NitroClient, confErr *nitroError, entityName, entityType string) (string, string) {
	entityCertName := ""
	rootCertName := ""
	if sslObj.Cert != "" {
		entityCertName = GetNSCompatibleNameHash(sslObj.Cert, 63)
		entityKeyName := GetNSCompatibleNameHash(sslObj.PrivateKey, 63)
		if isCertBindingPresent(client, entityName, entityCertName, entityType) == false {
			_, err := client.FindResource(netscaler.Sslcertkey.Type(), entityCertName)
			if err != nil {
				confErr.updateError(UploadCertData(client, []byte(sslObj.Cert), entityCertName, []byte(sslObj.PrivateKey), entityKeyName))
				confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslcertkey.Type(), entityCertName, ssl.Sslcertkey{Certkey: entityCertName, Cert: sslCertPath + entityCertName, Key: sslCertPath + entityKeyName}, "add"}, nil, nil))
			}
		}
	}
	if sslObj.RootCert != "" {
		rootCertName = GetNSCompatibleNameHash(sslObj.RootCert, 63)
		if isCertBindingPresent(client, entityName, rootCertName, entityType) == false {
			_, err := client.FindResource(netscaler.Sslcertkey.Type(), rootCertName)
			if err != nil {
				confErr.updateError(UploadCertData(client, []byte(sslObj.RootCert), rootCertName, nil, ""))
				confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslcertkey.Type(), rootCertName, ssl.Sslcertkey{Certkey: rootCertName, Cert: sslCertPath + rootCertName}, "add"}, nil, nil))
			}
		}
	}
	return entityCertName, rootCertName
}

// CertInfo structure holds info for certFile
type CertInfo struct {
	certName string
	isCA     bool
}

// deleteStaleCert will remove stale certificate bounds to SSL ServiceGroup/SSL Vserver where cert map will contain name of current certificates/rootCA
func deleteStaleCert(client *netscaler.NitroClient, confErr *nitroError, entityName, entityType, resourceName string, cert map[string]CertInfo) {
	certBindings, err := client.FindResourceArray(entityType, entityName)
	if err == nil {
		for _, certBinding := range certBindings {
			if certKey, err := getValueString(certBinding, "certkeyname"); err == nil {
				if _, ok := cert[certKey]; !ok {
					confErr.updateError(doNitro(client, nitroConfig{entityType, entityName, map[string]string{resourceName: entityName, "certkeyname": certKey, "ca": strconv.FormatBool(cert[certKey].isCA)}, "delete"}, nil, nil))
					DeleteCertKey(client, certKey)
				}
			}
		}
	}
}

func addSSLServiceGroup(client *netscaler.NitroClient, serviceGroupName string, sslObjs []SSLSpec, confErr *nitroError) {
	serverAuth := "DISABLED"
	certPresent := make(map[string]CertInfo)
	var entityCertName, rootCertName string
	for _, sslObj := range sslObjs {
		if sslObj.Cert != "" {
			entityCertName, rootCertName = sslObj.addInlineCert(client, confErr, serviceGroupName, netscaler.Sslservicegroup_sslcertkey_binding.Type())
		} else {
			entityCertName = sslObj.CertFilename
			rootCertName = sslObj.RootCertFilename
			AddCertKey(client, sslObj.CertFilename, sslObj.PrivateKeyFilename)
			if sslObj.RootCertFilename != "" {
				AddCertKey(client, sslObj.RootCertFilename, "")
			}
		}
		if entityCertName != "" {
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslservicegroup_sslcertkey_binding.Type(), serviceGroupName, ssl.Sslservicegroupsslcertkeybinding{Servicegroupname: serviceGroupName, Certkeyname: entityCertName}, "add"}, nil, nil))
			certPresent[entityCertName] = CertInfo{certName: entityCertName, isCA: false}
		}
		if rootCertName != "" {
			serverAuth = "ENABLED"
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslservicegroup_sslcertkey_binding.Type(), serviceGroupName, ssl.Sslservicegroupsslcertkeybinding{Servicegroupname: serviceGroupName, Certkeyname: rootCertName, Ca: true}, "add"}, nil, nil))
			certPresent[rootCertName] = CertInfo{certName: rootCertName, isCA: true}
		}
	}
	deleteStaleCert(client, confErr, serviceGroupName, netscaler.Sslservicegroup_sslcertkey_binding.Type(), "servicegroupname", certPresent)
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslservicegroup.Type(), serviceGroupName, ssl.Sslservicegroup{Servicegroupname: serviceGroupName, Serverauth: serverAuth}, "add"}, nil, nil))
}

func addSSLVserver(client *netscaler.NitroClient, vserverName string, sslObjs []SSLSpec, SSLClientAuth bool, confErr *nitroError) {
	sniEnable := "DISABLED"
	certPresent := make(map[string]CertInfo)
	var entityCertName, rootCertName string
	for _, sslObj := range sslObjs {
		if sslObj.Cert != "" {
			entityCertName, rootCertName = sslObj.addInlineCert(client, confErr, vserverName, netscaler.Sslvserver_sslcertkey_binding.Type())
		} else {
			entityCertName = sslObj.CertFilename
			AddCertKey(client, sslObj.CertFilename, sslObj.PrivateKeyFilename)
			if sslObj.RootCertFilename != "" {
				AddCertKey(client, sslObj.RootCertFilename, "")
			}
			rootCertName = sslObj.RootCertFilename
		}
		if entityCertName != "" {
			if sslObj.SNICert == true {
				sniEnable = "ENABLED"
			}
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslvserver_sslcertkey_binding.Type(), vserverName, ssl.Sslvserversslcertkeybinding{Vservername: vserverName, Certkeyname: entityCertName, Snicert: sslObj.SNICert}, "add"}, nil, nil))
			certPresent[entityCertName] = CertInfo{certName: entityCertName, isCA: false}
		}
		if rootCertName != "" {
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslvserver_sslcertkey_binding.Type(), vserverName, ssl.Sslvserversslcertkeybinding{Vservername: vserverName, Certkeyname: rootCertName, Ca: true}, "add"}, nil, nil))
			certPresent[rootCertName] = CertInfo{certName: rootCertName, isCA: true}
		}
	}
	sslClientAuthVal := "DISABLED"
	if SSLClientAuth == true {
		sslClientAuthVal = "ENABLED"
	}
	deleteStaleCert(client, confErr, vserverName, netscaler.Sslvserver_sslcertkey_binding.Type(), "vservername", certPresent)
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Sslvserver.Type(), vserverName, ssl.Sslvserver{Vservername: vserverName, Snienable: sniEnable, Clientauth: sslClientAuthVal}, "set"}, nil, nil))

}

func sslFileTransfer(client *netscaler.NitroClient, fileName, fileContents string) error {
	log.Printf("[DEBUG] NetScaler SSL file transfer %s", fileName)
	return doNitro(client, nitroConfig{netscaler.Systemfile.Type(), fileName, system.Systemfile{Fileencoding: "BASE64", Filelocation: sslCertPath, Filecontent: fileContents, Filename: fileName}, "add"}, nil, nil)
}

// UploadCert upload a certificate and key on to the Citrix-ADC
func UploadCert(client *netscaler.NitroClient, certPath, certNsFileName, keyPath, keyNsFileName string) error {
	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		log.Println("[ERROR] Reading File", certPath, err)
		return err
	}
	var keyData []byte
	if keyPath != "" {
		keyData, err = ioutil.ReadFile(keyPath)
		if err != nil {
			log.Println("[ERROR] Reading File:", keyPath, err)
			return err
		}
	}
	return UploadCertData(client, certData, certNsFileName, keyData, keyNsFileName)
}

// UploadCertData uploads a certificate(by content) and key on to the Citrix-ADC
func UploadCertData(client *netscaler.NitroClient, certData []byte, certNsFileName string, keyData []byte, keyNsFileName string) error {
	confErr := newNitroError()
	DeleteCert(client, certNsFileName)
	confErr.updateError(sslFileTransfer(client, certNsFileName, base64.StdEncoding.EncodeToString(certData)))
	if keyNsFileName != "" {
		DeleteCert(client, keyNsFileName)
		confErr.updateError(sslFileTransfer(client, keyNsFileName, base64.StdEncoding.EncodeToString(keyData)))
	}
	return confErr.getError()
}

// DeleteCert deleted a certificate/key from the Citrix-ADC
func DeleteCert(client *netscaler.NitroClient, fileName string) error {
	return client.DeleteResourceWithArgsMap(netscaler.Systemfile.Type(), fileName, map[string]string{"filelocation": encodedSSLCertPath})
}

// UpdateCert updates the ssl certkey on the Citrix-ADC
func UpdateCert(client *netscaler.NitroClient, certKeyName, certFileName, keyFileName string) error {
	sslCertKey := ssl.Sslcertkey{Certkey: certKeyName, Cert: certFileName, Nodomaincheck: true}
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
	removeCertBindings(client, confErr, netscaler.Sslvserver.Type(), vserverName, "vservername", netscaler.Sslvserver_sslcertkey_binding.Type())
}

// deleteCertBindings removes all the cert bindings which will be called from either SSL Servicegroup Delete or SSL Vserver
func deleteCertBindings(client *netscaler.NitroClient, confErr *nitroError, entityName, bindingType, resourceName string, certBindings []map[string]interface{}) {
	for _, certBinding := range certBindings {
		if certKey, err := getValueString(certBinding, "certkeyname"); err == nil {
			if caVal, ok := certBinding["ca"]; ok && caVal == true {
				confErr.updateError(doNitro(client, nitroConfig{bindingType, entityName, map[string]string{resourceName: entityName, "certkeyname": certKey, "ca": "true"}, "delete"}, nil, nil))

			} else {
				confErr.updateError(doNitro(client, nitroConfig{bindingType, entityName, map[string]string{resourceName: entityName, "certkeyname": certKey}, "delete"}, nil, nil))
			}
			DeleteCertKey(client, certKey)
		}
	}
}

// removeCertBindings will check and deletesCertBindings
func removeCertBindings(client *netscaler.NitroClient, confErr *nitroError, entityType, entityName, resourceName, bindingType string) {
	_, err := client.FindResource(entityType, entityName)
	if err == nil {
		certBindings, err := client.FindResourceArray(bindingType, entityName)
		if err == nil {
			deleteCertBindings(client, confErr, bindingType, entityName, resourceName, certBindings)
		}
	}

}
