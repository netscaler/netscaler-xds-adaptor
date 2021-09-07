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

package adsclient

import (
	"citrix-xds-adaptor/nsconfigengine"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
)

// Watcher is for watching certificate directory
type Watcher struct {
	dirNames   map[string]map[string]string
	nsConfig   *configAdaptor
	watcher    *fsnotify.Watcher
	watcherMux sync.Mutex
	stopCh     chan bool
}

// StartCertWatcher will start the Certificate Watcher
func (client *AdsClient) StartCertWatcher(errCh chan<- error) error {
	w, err := newWatcher()
	if err != nil {
		xDSLogger.Error("StartCertWatcher: Could not create new watcher", "error", err.Error())
		return err
	}
	client.certWatcherMux.Lock()
	client.certWatcher = w
	client.certWatcherMux.Unlock()
	go client.certWatcher.Run(errCh)
	return nil
}
func newWatcher() (*Watcher, error) {
	var err error
	watch := &Watcher{
		dirNames: make(map[string]map[string]string),
	}
	watch.stopCh = make(chan bool, 1)
	watch.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		xDSLogger.Error("newWatcher: Failed to create Watcher", "error", err)
		return nil, err
	}
	return watch, nil
}
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
func getDirFileName(fileName string) (string, string) {
	delimiter := "/"
	slice := strings.Split(fileName, delimiter)
	return strings.Join(slice[0:len(slice)-1], delimiter), slice[len(slice)-1]

}
func getFileContent(fileName string) ([]byte, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		xDSLogger.Error("Could not read file", "fileName", fileName, "error", err)
	}
	return data, err
}

func findCertChainLength(certChainFile string) (int, error) {
	certChainBytes, err := getFileContent(certChainFile)
	if err != nil {
		return 0, err
	}
	parsedLen := 0
	data := certChainBytes
	cLen := 0
	for len(data) > 0 {
		cb, _ := pem.Decode(data)
		if cb == nil {
			// Last block invalid
			return cLen, nil
		}
		parsedLen += len(cb.Bytes)
		data = certChainBytes[parsedLen:len(certChainBytes)]
		cLen++
	}
	return cLen, nil
}

func getCertKeyData(certPath, keyPath string) ([]byte, []byte, error) {
	var certData, keyData []byte
	var err error
	certData, err = getFileContent(certPath)
	if err != nil {
		xDSLogger.Error("getCertKeyData: Could not read certificate", "certPath", certPath, "error", err)
		return certData, keyData, err
	}
	if keyPath != "" {
		keyData, err = getFileContent(keyPath)
		if err != nil {
			xDSLogger.Error("getCertKeyData: Could not read key", "keyPath", keyPath, "error", err)
			return certData, keyData, err
		}
	}
	return certData, keyData, nil
}

//addDir will add the Directory which contains certFile for monitoring, if not already added
//CertFile and KeyFile (optional for rootCert) will be uploaded to Citrix ADC if not previously done.
//This function also add certKey and rootKey in Citrix ADC
func (w *Watcher) addDir(certPath, keyPath string) (string, string, string, error) {
	dirName, certFile := getDirFileName(certPath)
	keyFile := ""
	var ok bool
	if _, ok = w.dirNames[dirName]; !ok {
		err := w.watcher.Add(dirName)
		if err != nil {
			xDSLogger.Error("addDir: Failed to add directory to watcher", "dirName", dirName, "err", err)
			return "", "", "", err
		}
		xDSLogger.Debug("addDir: Directory added for monitoring", "dirName", dirName)
		w.dirNames[dirName] = make(map[string]string)
	}
	if fileExists(certPath) {
		certData, keyData, err := getCertKeyData(certPath, keyPath)
		if err != nil {
			return "", "", "", err
		}
		nsCertOrRootCertFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(certData)), 55)
		nsKeyFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(keyData)), 55)
		xDSLogger.Trace("addDir: Adding CertFile and keyFile on ADC", "nsCertFile", nsCertOrRootCertFileName, "nsKeyFile", nsKeyFileName)
		if nsconfigengine.IsCertKeyPresent(w.nsConfig.client, nsCertOrRootCertFileName, nsKeyFileName) == false {
			xDSLogger.Trace("addDir: Added certificate File", "certFile", certFile)
			if keyPath != "" {
				_, keyFile = getDirFileName(keyPath)
				totalCerts, err := findCertChainLength(certPath)
				//Delete Intermediate Certificate Files
				if err == nil && totalCerts > 1 {
					for i := 1; i < totalCerts; i++ {
						nsconfigengine.DeleteCert(w.nsConfig.client, nsCertOrRootCertFileName+"_ic"+strconv.Itoa(i))
					}
				}
				// Updating fields before UploadCertData
				xDSLogger.Trace("addDir: Added Key File", "keyFile", keyFile)
				w.dirNames[dirName]["certFile"] = certFile
				w.dirNames[dirName]["keyFile"] = keyFile
				w.dirNames[dirName]["nsCertFileName"] = nsCertOrRootCertFileName
				w.dirNames[dirName]["nsKeyFileName"] = nsKeyFileName
				w.dirNames[dirName]["nsRootCertFile"] = ""
				if multiClusterIngress && totalCerts > 1 {
					w.dirNames[dirName]["nsRootCertFile"] = nsCertOrRootCertFileName + "_ic" + strconv.Itoa(totalCerts-1)
				}
			} else { //root certificate
				xDSLogger.Trace("addDir: Added rootCert file", "certFile", certFile)
				w.dirNames[dirName]["rootCertFile"] = certFile
				w.dirNames[dirName]["nsRootCertFile"] = nsCertOrRootCertFileName
			}

			err := nsconfigengine.UploadCertData(w.nsConfig.client, certData, nsCertOrRootCertFileName, keyData, nsKeyFileName)
			if err != nil {
				// reset fields of dirName
				w.dirNames[dirName]["certFile"] = ""
				w.dirNames[dirName]["keyFile"] = ""
				w.dirNames[dirName]["nsCertFileName"] = ""
				w.dirNames[dirName]["nsKeyFileName"] = ""
				w.dirNames[dirName]["nsRootCertFile"] = ""
				xDSLogger.Error("addDir: Certificate/key upload to ADC failed.", "nsCertFileName", nsCertOrRootCertFileName, "error", err)
				return "", "", "", err
			}
		} else {
			xDSLogger.Trace("addDir: Cert/Key File already present", "certFile", certFile)
		}
	}
	return w.dirNames[dirName]["nsCertFileName"], w.dirNames[dirName]["nsKeyFileName"], w.dirNames[dirName]["nsRootCertFile"], nil
}

// Run is a thread which will alert whenever files in the directory added for watch gets updated.
func (w *Watcher) Run(errCh chan<- error) {
	for {
		select {
		case <-w.stopCh:
			xDSLogger.Info("xDS-adaptor's Certificate watcher thread stopped")
			errCh <- fmt.Errorf("xDS-adaptor's Certificate watcher thread stopped")
			return
		case event, ok := <-w.watcher.Events:
			if !ok {
				xDSLogger.Error("Error watching certificate related events")
				errCh <- fmt.Errorf("Error watching certificate related events")
				return
			}
			w.watcherMux.Lock()
			xDSLogger.Trace("Watcher captured event", "event", event)
			if (event.Op&fsnotify.Remove == fsnotify.Remove) || (event.Op&fsnotify.Write == fsnotify.Write) {
				xDSLogger.Debug("Watcher folder got updated", "eventName", event.Name)
				// strings.Contains(event.Name, "..") this is for mounted certificates
				//strings.Contains(event.Name, ClientCertChainFile)  for CSR generated
				if !strings.Contains(event.Name, "..") && !strings.Contains(event.Name, ClientCertChainFile) {
					xDSLogger.Debug("File not considered for update", "fileName", event.Name)
				} else {
					uploadFilePath, _ := getDirFileName(event.Name)
					xDSLogger.Trace("Uploading files from directory", "dirName", uploadFilePath)
					if w.dirNames[uploadFilePath]["certFile"] != "" {
						certFile := uploadFilePath + "/" + w.dirNames[uploadFilePath]["certFile"]
						keyFile := uploadFilePath + "/" + w.dirNames[uploadFilePath]["keyFile"]
						xDSLogger.Trace("Uploading certFile to ADC", "certFile", certFile)
						xDSLogger.Trace("Uploading keyfile to ADC", "keyFile", keyFile)
						if fileExists(certFile) {
							certData, keyData, err := getCertKeyData(certFile, keyFile)
							if err == nil {
								nsCertFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(certData)), 55)
								nsKeyFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(keyData)), 55)
								/* if CertKey and KeyFile did not change then do not update */
								if nsconfigengine.IsCertKeyPresent(w.nsConfig.client, nsCertFileName, nsKeyFileName) == false {
									xDSLogger.Debug("Uploading and updating bindings on ADC for cert/key", "certFile", certFile, "nsCertName", nsCertFileName, "nsKeyName", nsKeyFileName)
									nsconfigengine.UploadCertData(w.nsConfig.client, certData, nsCertFileName, keyData, nsKeyFileName)
									rootFileName, err := nsconfigengine.UpdateBindings(w.nsConfig.client, w.dirNames[uploadFilePath]["nsCertFileName"], w.dirNames[uploadFilePath]["nsCertFileName"], nsCertFileName, nsKeyFileName, multiClusterIngress)
									if err == nil {
										w.dirNames[uploadFilePath]["nsCertFileName"] = nsCertFileName
										w.dirNames[uploadFilePath]["nsKeyFileName"] = nsKeyFileName
										w.dirNames[uploadFilePath]["nsRootCertFile"] = rootFileName
									}
								}
							}
						}
					}
					if w.dirNames[uploadFilePath]["rootCertFile"] != "" {
						certFile := uploadFilePath + "/" + w.dirNames[uploadFilePath]["rootCertFile"]
						if fileExists(certFile) {
							certData, _, err := getCertKeyData(certFile, "")
							if err == nil {
								nsRootFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(certData)), 55)
								xDSLogger.Debug("Uploading and updating bindings of rootCert", "certFile", certFile, "nsRootFileName", nsRootFileName)
								var keyData []byte
								nsconfigengine.UploadCertData(w.nsConfig.client, certData, nsRootFileName, keyData, "")
								nsconfigengine.AddCertKey(w.nsConfig.client, nsRootFileName, "", false)
								nsconfigengine.UpdateRootCABindings(w.nsConfig.client, w.dirNames[uploadFilePath]["nsRootFileName"], nsRootFileName)
								nsconfigengine.DeleteCertKey(w.nsConfig.client, w.dirNames[uploadFilePath]["nsRootFileName"])
								w.dirNames[uploadFilePath]["nsRootFileName"] = nsRootFileName
							}
						}
					}
				}
			}
			w.watcherMux.Unlock()
		case err, ok := <-w.watcher.Errors:
			if !ok {
				errCh <- fmt.Errorf("Certificate watcher encountered issue in monitoring events ")
				return
			}
			xDSLogger.Error("Watcher error", "error", err)
		}
	}
}

// Stop function would stop the watcher
func (w *Watcher) Stop() {
	if w.watcher != nil {
		w.watcher.Close()
		xDSLogger.Trace("Watcher is closed for directory", "dirName", w.dirNames)
	}
	w.nsConfig = nil
	w.stopCh <- true
	xDSLogger.Debug("Watcher is stopped for directory", "dirName", w.dirNames)
}
