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

package main

import (
	"citrix-istio-adaptor/adsclient"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
)

const (
	userFile    = "/etc/nslogin/username"
	passFile    = "/etc/nslogin/password"
	versionFile = "/etc/Version"
)

func getCredentials(uFile, pFile string) (string, string, error) {
	userName := os.Getenv("NS_USER")
	passWord := os.Getenv("NS_PASSWORD")

	// If secret is specified, retrieve Username/password from secret and ignore Env variable info
	if _, err := os.Stat(uFile); err == nil { // If file exists
		user, err := ioutil.ReadFile(uFile)
		if err != nil {
			return "", "", fmt.Errorf("Not able to retrieve credentials. Verify that the secret is properly created and mounted")
		}
		// user is a []byte
		userName = string(user)
	}

	// Retrieve Password from secret
	if _, err := os.Stat(pFile); err == nil { // If file exists
		pass, err := ioutil.ReadFile(pFile)
		if err != nil {
			return "", "", fmt.Errorf("Not able to retrieve credentials. Verify that the secret is properly created and mounted")
		}
		// pass is a []byte
		passWord = string(pass)
	}
	return userName, passWord, nil
}

func getVserverIP(vserverIP string, proxyType string) (string, error) {
	if vserverIP != "" {
		ip := net.ParseIP(vserverIP)
		if ip == nil {
			return "", fmt.Errorf("Not a valid IP address")
		}
		if strings.Contains(vserverIP, ":") {
			return "", fmt.Errorf("Not a valid IPv4 address")
		}
		return vserverIP, nil
	} else if proxyType == "router" {
		return "nsip", nil
	}
	return "", nil
}

func getIstioAdaptorVersion() (string, error) {
	if _, err := os.Stat(versionFile); err == nil { // If file exists
		fileContent, err := ioutil.ReadFile(versionFile)
		if err != nil {
			return "", fmt.Errorf("Not able to read file %s", versionFile)
		}
		return string(fileContent), nil
	}
	return "", fmt.Errorf("Version File does not exist")
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	pilotURL := flag.String("pilot-location", "istio-pilot.istio-system:15011", "ip/hostname:port location of istio-pilot secure grpc server")
	netscalerURL := flag.String("netscaler-url", "http://127.0.0.1", "http(s)://ip|hostname:port location of the  netscaler to configure")
	secureConnect := flag.Bool("secure-connect", true, "If this flag is present, secure connection to istio-pilot is attempted. ")
	vserverIP := flag.String("vserver-ip", "", "The vserver IP for the MPX/VPX ingress gateway")
	proxyType := flag.String("proxy-type", "sidecar", "Type of proxy - sidecar, ingress, router")
	pilotSAN := flag.String("pilot-SAN", "spiffe://cluster.local/ns/istio-system/sa/istio-pilot-service-account",
		"Subject Alternative Name for istio-pilot which SPIFFE ID of the Istio Pilot in given case. "+
			"The format of this SPIFFE ID is spiffe://<spiffe_trustDomain>/ns/<namespace_of_istio-pilot>/sa/<serviceaccount_of_istio-pilot> "+
			"By default, trustDomain is cluster.local. Namespace is istio-system. SA: istio-pilot-service-account "+
			"Default value of pilotSAN spiffe://cluster.local/ns/istio-system/sa/istio-pilot-service-account")
	netProfile := flag.String("net-profile", "",
		"Name of the network profile which is created by Citrix Node Controller (CNC) on VPX/MPX device. "+
			"This is required to establish connectivity to the pod network from Citrix ADC VPX/MPX")
	version := flag.Bool("version", false, "Use this flag to print the Version of Istio-adaptor")
	analyticsServerIP := flag.String("adm-ip", "", "Licensing server IP(usually Citrix ADM IP)")
	logProxyURL := flag.String("coe-url", "", "Citrix-Observability-Exporter(Logproxy) service name.")
	flag.Parse()
	versionIA, err := getIstioAdaptorVersion()
	if err != nil {
		fmt.Printf("[ERROR] Could not get Istio-Adaptor Version. %v\n", err)
	} else {
		fmt.Printf("[INFO] Istio-Adaptor Version: %s\n", strings.Replace(versionIA, "\n", "\t", 2))
	}
	if *version {
		os.Exit(0)
	}
	userName, passWord, err := getCredentials(userFile, passFile)
	if err != nil {
		log.Printf("[ERROR] %v. Username and/or password must be mentioned via Secret!", err)
		os.Exit(1)
	}
	vsvrIP, errVserverIP := getVserverIP(*vserverIP, *proxyType)
	if errVserverIP != nil {
		log.Printf("[ERROR] Incorrect vserverIP '%s': %v", *vserverIP, errVserverIP)
		os.Exit(1)
	}
	log.Printf("[TRACE]: secureConnect: %v", *secureConnect)
	nodeID := *proxyType + "~" + os.Getenv("INSTANCE_IP") + "~" + os.Getenv("POD_NAME") + "." + os.Getenv("POD_NAMESPACE") + "~" + os.Getenv("POD_NAMESPACE") + ".svc.cluster.local"
	discoveryClient, err := adsclient.NewAdsClient(*pilotURL, *pilotSAN, *secureConnect, nodeID, os.Getenv("APPLICATION_NAME"), *netscalerURL, userName, passWord, vsvrIP, *netProfile, *analyticsServerIP, *logProxyURL)
	if err != nil {
		log.Printf("[ERROR] Unable to initialize ADS client: %v", err)
		os.Exit(1)
	}
	discoveryClient.StartClient()
	<-make(chan int)
}
