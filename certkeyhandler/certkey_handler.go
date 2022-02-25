/*
Copyright 2022 Citrix Systems, Inc
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
	"bufio"
	"log"
	"strings"

	"context"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/hashicorp/go-hclog"
	caclient "istio.io/istio/security/pkg/caclient"
	citadel "istio.io/istio/security/pkg/nodeagent/caclient/providers/citadel"
	pkiutil "istio.io/istio/security/pkg/pki/util"
	"istio.io/istio/security/pkg/util"
)

var (
	tokenFile           = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	thirdPartyTokenFile = "/var/run/secrets/tokens/istio-token"
	now                 = time.Now()
	citadelName         = "Istiod"
	csrMaxRetries       = 3
	csrRetrialInterval  = 5 * time.Second
	rootCertFilePath    = "/etc/certs/root-cert.pem"
	ckLogger            hclog.Logger
)

// CADetails store info about CA endpoint as well as workload (CA client)
type CADetails struct {
	// CAAddress is address of CA to which xdsadaptor acting as CA client connects to
	CAAddress string
	// CertTTL is the validity of certificate
	CertTTL time.Duration
	// Env tells where CA client is running. For now, it is onprem.
	Env string
	// ClusterID field holds Kubernetes value
	ClusterID string
	// TrustDomain is the trust domain part of SPIFFE URI
	TrustDomain string
	// NameSpace of the workload
	NameSpace string
	// ServiceAccount of the workload
	SAName string
	// CAProvider tells who is the CA
	CAProvider string
}

// CertDetails hold information about Certificates' & Key's location and keysize
type CertDetails struct {
	RootCertFile string
	// CertFile is location of workload certificate which would be signed by CA
	CertFile string
	// CertChainFile is location of certificate chain of the CA client, including the workload cert
	CertChainFile string
	// KeyFile is location of private key file
	KeyFile string
	// RSAKeySize
	RSAKeySize int
	// Organization name
	Org string
}

// CertKeyHandler store info needed to generate CSR and certificate rotation
type CertKeyHandler struct {
	// CAAddress is address of CA to which xdsadaptor acting as CA client connects to
	CAAddress string
	// CertTTL is the validity of certificate
	CertTTL time.Duration
	// Env tells where CA client is running. For now, it is onprem.
	Env string
	// ClusterID field holds Kubernetes value
	ClusterID string
	// HostName is the SPIFFE id in the form of "spiffe://trust-domain/ns/namespace/sa/serviceaccount"
	HostName string
	// RootCertFile is location of root certificate
	RootCertFile string
	// CertFile is location of workload certificate which would be signed by CA
	CertFile string
	// CertChainFile is location of certificate chain of the CA client, including the workload cert
	CertChainFile string
	// KeyFile is location of private key file
	KeyFile string
	// RSAKeySize
	RSAKeySize int
	// Organization name
	Org string
	// CAProvider tells who is the CA. Currently, only Istiod is supported.
	CAProvider string
	// CSRMaxRetries: Max no. of attempts for certificate requests
	CSRMaxRetries int
	// CSRInitialRetrialInterval is the retrial interval for certificate requests.
	CSRInitialRetrialInterval time.Duration
	// TokenFile is the token file path. If not provided, standard token-path (defined by tokenFile global var) is chosen
	TokenFile string
	// rotator is keyCert rotator
	rotator *caclient.KeyCertBundleRotator
	// Key and certificate bundler
	keyCertBundle pkiutil.KeyCertBundle
	stopCh        chan bool
	stopped       bool
	tls           bool
}

type citadelClientInfo struct {
	CAAddress         string
	rootCertFile      string
	clusterID         string
	tokenFile         string
	csrPEM            []byte
	certValidityInSec int64
	tls               bool
}

func init() {
	/* Create a logger */
	level := hclog.LevelFromString("DEBUG") // Default level
	logLevel, ok := os.LookupEnv("LOGLEVEL")
	if ok {
		lvl := hclog.LevelFromString(logLevel)
		if lvl != hclog.NoLevel {
			level = lvl
		} else {
			log.Printf("CertKey handler: LOGLEVEL not set to a valid log level (%s), defaulting to %d", logLevel, level)
		}
	}
	_, jsonLog := os.LookupEnv("JSONLOG")
	ckLogger = hclog.New(&hclog.LoggerOptions{
		Name:            "xDS-Adaptor",
		Level:           level,
		Color:           hclog.AutoColor,
		JSONFormat:      jsonLog,
		IncludeLocation: true,
	})
	log.Printf("[INFO] CertKey handler logger created with loglevel = %sand jsonLog = %v", level, jsonLog)
}

// NewCertKeyHandler function creates a certificate and key handler for xds-adaptor
func NewCertKeyHandler(cainfo *CADetails, certinfo *CertDetails) (*CertKeyHandler, error) {
	ckh := new(CertKeyHandler)
	ckh.CAAddress = cainfo.CAAddress
	ckh.CertTTL = cainfo.CertTTL
	ckh.Env = cainfo.Env
	ckh.ClusterID = cainfo.ClusterID
	ckh.HostName = "spiffe://" + cainfo.TrustDomain + "/ns/" + cainfo.NameSpace + "/sa/" + cainfo.SAName
	ckh.RootCertFile = certinfo.RootCertFile   //CAcertFile
	ckh.CertFile = certinfo.CertFile           //ClientCertFile
	ckh.CertChainFile = certinfo.CertChainFile //ClientCertChainFile
	ckh.KeyFile = certinfo.KeyFile             //ClientKeyFile
	ckh.RSAKeySize = certinfo.RSAKeySize       //rsaKeySize
	ckh.Org = certinfo.Org                     //orgName
	ckh.CAProvider = cainfo.CAProvider
	ckh.CSRMaxRetries = csrMaxRetries
	ckh.CSRInitialRetrialInterval = csrRetrialInterval
	ckh.stopCh = make(chan bool, 1)
	ckh.stopped = true
	ckh.tls = true
	ckh.TokenFile = tokenFile
	if strings.EqualFold(os.Getenv("JWT_POLICY"), "third-party-jwt") {
		ckh.TokenFile = thirdPartyTokenFile
		ckLogger.Trace("NewCertKeyHandler: Third party token file.")
	}
	return ckh, nil
}

// SetLogLevel function sets the log level of certkey handler package
func SetLogLevel(level string) {
	ckLogger.SetLevel(hclog.LevelFromString(level))
}

// Write a string slice to file
func writeStringArrToFile(strarr []string, fileName string) error {
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		ckLogger.Error("Failed to create file", "fileName", fileName, "error", err.Error())
		return err
	}
	datawriter := bufio.NewWriter(file)
	for _, data := range strarr {
		_, _ = datawriter.WriteString(data)
	}
	datawriter.Flush()
	file.Close()
	return nil
}

func getToken(tokenfile string) (string, error) {
	tokenBytes, _ := ioutil.ReadFile(tokenfile)
	return string(tokenBytes), nil
}

func getCertBytes(certfile string) ([]byte, error) {
	certbytes, err := ioutil.ReadFile(certfile)
	if err != nil {
		fmt.Printf("Could not read Certificate %s. Error: %s\n", certfile, err.Error())
		return nil, err
	}
	return certbytes, nil
}

// getCertFromCitadel function creates a Citadel CA client, and returns certificate-chain if CSR sign is successful
func getCertFromCitadel(clientInfo citadelClientInfo) ([]string, error) {
	token, _ := getToken(clientInfo.tokenFile)
	rootCertBytes, err := ioutil.ReadFile(clientInfo.rootCertFile)
	cli, err := citadel.NewCitadelClient(clientInfo.CAAddress, clientInfo.tls, rootCertBytes, clientInfo.clusterID)
	if err != nil {
		ckLogger.Error("getCertFromCitadel: Could not create Citadel client", "CAAddress", clientInfo.CAAddress, "error", err.Error())
		return nil, err
	}
	ckLogger.Debug("getCertFromCitadel: Citadel Client created successfully", "CAAddress", clientInfo.CAAddress, "Cluster-ID", clientInfo.clusterID)
	certChain, err := cli.CSRSign(context.Background(), "citrix-reqid", clientInfo.csrPEM, token, clientInfo.certValidityInSec)
	if err != nil {
		ckLogger.Error("getCertFromCitadel: Could not get CSR signed by CA", "CAAddress", clientInfo.CAAddress, "error", err.Error())
		return nil, err
	}
	return certChain, nil
}

func (ckh *CertKeyHandler) getCertKeyRotator() error {
	var cfg *caclient.Config
	cfg = &caclient.Config{
		RootCertFile:              ckh.RootCertFile,
		CertFile:                  ckh.CertFile,
		KeyFile:                   ckh.KeyFile,
		CertChainFile:             ckh.CertChainFile,
		Env:                       ckh.Env,
		CAAddress:                 ckh.CAAddress,
		Org:                       ckh.Org,
		RequestedCertTTL:          ckh.CertTTL, // in time.Duration
		CSRMaxRetries:             ckh.CSRMaxRetries,
		CSRInitialRetrialInterval: ckh.CSRInitialRetrialInterval,
		ForCA:                     false,
	}

	// Check for certificate validity.
	// It has been observed that CA issued certificate having NotBefore time ahead of currentTime.
	// Sleep for the difference before creating CertificateKey Bundle
	certBytes, _ := ioutil.ReadFile(ckh.CertFile)
	cert, err := pkiutil.ParsePemEncodedCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("[ERROR] Failed to parse PEM certificate: %v", err)
	}
	currentTime := time.Now()
	diff := cert.NotBefore.Sub(currentTime)
	time.Sleep(diff) // diff can have negative value, and Sleep function handles negative values by not sleeping

	// Create key-certificate bundle from existing key and certificates
	// initially cert file would be same as certChain file
	keyCertBundle, err := pkiutil.NewVerifiedKeyCertBundleFromFile(ckh.CertFile, ckh.KeyFile, ckh.CertChainFile, ckh.RootCertFile)
	if err != nil {
		ckLogger.Error("getCertKeyRotator: Could not create keyCertBundle", "error", err.Error())
		return err
	}

	// Create keyCertBundle Rotator
	rotator, err := caclient.NewKeyCertBundleRotator(cfg, keyCertBundle)
	if err != nil {
		ckLogger.Error("getCertKeyRotator: Could not create keyCertBundler Rotator", "error", err.Error())
		return err
	}
	ckh.keyCertBundle = keyCertBundle
	ckh.rotator = rotator
	return nil
}

func writeToFile(filename string, pemdata []byte) error {
	// Store PEM encoded certificate key in files
	err := ioutil.WriteFile(filename, pemdata, 0644)
	if err != nil {
		fmt.Printf("Could not write to file %s. Error: %s\n", filename, err.Error())
		return err
	}
	return nil
}

func (ckh *CertKeyHandler) updateCertsAndKey() {
	certBytes, privKeyBytes, certChainBytes, rcBytes := ckh.keyCertBundle.GetAllPem()
	/* Interestingly certChainBytes are empty!
	 * Append certBytes and rootCertBytes to create certChain
	 */
	if len(certChainBytes) == 0 {
		ckLogger.Trace("updateCertsAndKey: Empty certificate chain. Create certificate chain from cert file and rootcert file")
		certChainBytes = append(certBytes, rcBytes...)
	}
	// Update key and certificate files
	_ = writeToFile(ckh.KeyFile, privKeyBytes)
	_ = writeToFile(ckh.CertFile, certBytes)
	_ = writeToFile(ckh.CertChainFile, certChainBytes)
}

// StartHandler function starts the certificate-key handler and establishes connection with CA
func (ckh *CertKeyHandler) StartHandler(errCh chan<- error) {
	if !ckh.stopped {
		errCh <- fmt.Errorf("Certificate Key Handler already running")
		return
	}
	ckLogger.Trace("Certificate key handler started", "ckh", ckh)
	ckh.stopped = false

	defer func() {
		ckh.stopped = true
	}()

	var certChain []string
	// Ensure that certificate is always valid by setting starting time before the current time
	notBefore := now.Add(-1 * time.Minute)
	certOptions := pkiutil.CertOptions{
		Host:         ckh.HostName,
		NotBefore:    notBefore,
		TTL:          ckh.CertTTL,
		SignerCert:   nil,
		SignerPriv:   nil,
		Org:          ckh.Org,
		IsCA:         false, // Set to false as certificate is generated for client
		IsSelfSigned: false,
		IsClient:     true,
		IsServer:     true,
		RSAKeySize:   ckh.RSAKeySize,
	}

	// Generate CSR for the workload
	csrPem, privPem, err := pkiutil.GenCSR(certOptions)
	if err != nil {
		ckLogger.Error("StartHandler: Could not create Certificate Signing Request (CSR)", "error", err.Error())
		errCh <- fmt.Errorf("CSR generation failed")
		return
	}
	// Write privPem to keyFile
	err = ioutil.WriteFile(ckh.KeyFile, privPem, 0644)
	if err != nil {
		ckLogger.Error("StartHandler: Could not write Private Key to file", "error", err.Error())
		errCh <- fmt.Errorf("Private Key creation failed")
		return
	}

	switch ckh.CAProvider {
	case citadelName:
		cltinfo := citadelClientInfo{CAAddress: ckh.CAAddress, rootCertFile: ckh.RootCertFile, clusterID: ckh.ClusterID, tokenFile: ckh.TokenFile, csrPEM: csrPem, certValidityInSec: int64(ckh.CertTTL / time.Second), tls: ckh.tls}
		certChain, err = getCertFromCitadel(cltinfo)
		if err != nil {
			ckLogger.Error("StartHandler: Could not retrieve certificate from Citadel", "CAAddress", ckh.CAAddress, "error", err.Error())
			errCh <- fmt.Errorf("Citadel Client Error")
			return
		}
		// Istio Citadel expects root-cert also to be present in /etc/certs directory
		rootCertBytes, _ := ioutil.ReadFile(ckh.RootCertFile)
		_ = writeToFile(rootCertFilePath, rootCertBytes)
	default:
		errCh <- fmt.Errorf("StartHandler: CA provider %q isn't supported. Currently xDS-Adaptor supports Istiod/Citadel", ckh.CAProvider)
		return
	}

	// Initially store cert.pem same as cert-chain.pem
	_ = writeStringArrToFile(certChain, ckh.CertFile)
	// Write Certificate Chain obtained from CA to file
	_ = writeStringArrToFile(certChain, ckh.CertChainFile)

	if err := ckh.getCertKeyRotator(); err != nil {
		ckLogger.Error("StartHandler: Could not create keyCertBundler Rotator")
		errCh <- fmt.Errorf("Could not create keyCertBundler Rotator")
		return
	}
	rotatoErrCh := make(chan error)
	go ckh.rotator.Start(rotatoErrCh)
	defer ckh.rotator.Stop()
	for {
		certUtil := util.NewCertUtil(0)
		// retrieve certbytes from the certificate file. not from bundle.
		certBytes, _ := getCertBytes(ckh.CertFile)
		waitTime, _ := certUtil.GetWaitTime(certBytes, time.Now(), time.Duration(0))
		timer := time.NewTimer(waitTime)
		select {
		case <-ckh.stopCh:
			ckLogger.Info("StartHandler: Certificate Key Handler stopped")
			return
		case err := <-rotatoErrCh:
			timer.Stop()
			if err.Error() != "" {
				ckLogger.Error("StartHandler: Certificate key handler error", "error", err.Error())
				errCh <- fmt.Errorf("KeyCertBundler Rotator stopped")
				return
			}
		case <-timer.C:
			time.Sleep(1 * time.Second) // Certificate can expire at any microsecond in this one second duration
			ckLogger.Trace("StartHandler: Cert-expiry time passed. Check new certificate contents.")
			ckh.updateCertsAndKey()
		}
	}
}

// StopHandler will stop the certificate key handler
func (ckh *CertKeyHandler) StopHandler() {
	// Stop the rotator.
	if ckh.rotator != nil {
		ckh.rotator.Stop()
	}
	ckh.stopCh <- true // When StartHandler() returns, it will set ckh.stopped = true
	ckLogger.Trace("Stopped Certificate key handler")
}
