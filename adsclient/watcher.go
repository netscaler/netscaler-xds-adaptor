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
	"github.com/fsnotify/fsnotify"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
)

// Watcher is for watching certificate directory
type Watcher struct {
	dirNames   map[string]map[string]string
	nsConfig   *configAdaptor
	watcher    *fsnotify.Watcher
	watcherMux sync.Mutex
}

func newWatcher(nsConfig *configAdaptor) (*Watcher, error) {
	var err error
	watch := &Watcher{
		dirNames: make(map[string]map[string]string),
	}
	watch.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		log.Println("[ERROR] Failed to create fsnotify.Watcher:", err)
		return nil, err
	}
	watch.nsConfig = nsConfig
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
		log.Println("[ERROR] Reading File", data, err)
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
		log.Println("[ERROR] Reading File:", certPath, err)
		return certData, keyData, err
	}
	if keyPath != "" {
		keyData, err = getFileContent(keyPath)
		if err != nil {
			log.Println("[ERROR] Reading File:", keyPath, err)
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
			log.Println("[ERROR] Failed to add Directory Name to fsnotify.Watcher:", dirName, err)
			return "", "", "", err
		}
		log.Println("[DEBUG] Directory added for monitoring", dirName)
		w.dirNames[dirName] = make(map[string]string)
	}
	if keyPath != "" {
		if w.dirNames[dirName]["certFile"] == "" {
			log.Println("[DEBUG] Added Certificate File", certFile)
			_, keyFile = getDirFileName(keyPath)
			if fileExists(certPath) {
				certData, keyData, err := getCertKeyData(certPath, keyPath)
				if err != nil {
					return "", "", "", err
				}
				nsCertFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(certData)), 55)
				nsKeyFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(keyData)), 55)
				log.Println("[DEBUG] nsfileName", nsCertFileName, nsKeyFileName)
				totalCerts, err := findCertChainLength(certPath)
				//Delete Intermediate Certificate Files
				if err == nil && totalCerts > 1 {
					for i := 1; i < totalCerts; i++ {
						nsconfigengine.DeleteCert(w.nsConfig.client, nsCertFileName+"_ic"+strconv.Itoa(i))
					}
				}
				nsconfigengine.UploadCertData(w.nsConfig.client, certData, nsCertFileName, keyData, nsKeyFileName)
				//nsconfigengine.AddCertKey(w.nsConfig.client, nsCertFileName, nsKeyFileName)
				log.Println("[DEBUG] Added Key FIle", keyFile)
				w.dirNames[dirName]["certFile"] = certFile
				w.dirNames[dirName]["keyFile"] = keyFile
				w.dirNames[dirName]["nsCertFileName"] = nsCertFileName
				w.dirNames[dirName]["nsKeyFileName"] = nsKeyFileName
				w.dirNames[dirName]["nsRootCertFile"] = ""
				if totalCerts > 1 {
					w.dirNames[dirName]["nsRootCertFile"] = nsCertFileName + "_ic" + strconv.Itoa(totalCerts-1)
					/*certChain, err := nsconfigengine.GetCertChain(w.nsConfig.client, nsCertFileName)
					if err != nil {
						log.Println("[ERROR] Failed getting CertChain", nsCertFileName, err)
						return w.dirNames[dirName]["nsCertFileName"], w.dirNames[dirName]["nsKeyFileName"], w.dirNames[dirName]["nsRootCertFile"], err
					}
					if len(certChain) >= 1 {
						log.Println("[DEBUG] rootCertFile", certChain[len(certChain)-1])
						w.dirNames[dirName]["nsRootCertFile"] = certChain[len(certChain)-1]
					}*/
				}
			}
		} else {
			log.Println("[DEBUG] CertKey and KeyFile already added", certFile, keyFile)
		}
		return w.dirNames[dirName]["nsCertFileName"], w.dirNames[dirName]["nsKeyFileName"], w.dirNames[dirName]["nsRootCertFile"], nil
	}
	if w.dirNames[dirName]["rootCertFile"] == "" {
		w.dirNames[dirName]["rootCertFile"] = certFile
		log.Println("[DEBUG] Added rootCertFile FIle", certFile)
		var keyData []byte
		if fileExists(certPath) {
			certData, _, err := getCertKeyData(certPath, "")
			if err != nil {
				return "", "", "", err
			}
			nsRootFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(certData)), 55)
			w.dirNames[dirName]["nsRootCertFile"] = nsRootFileName
			log.Println("[DEBUG] nsRootfileName", nsRootFileName)
			nsconfigengine.UploadCertData(w.nsConfig.client, certData, nsRootFileName, keyData, "")
			//nsconfigengine.AddCertKey(w.nsConfig.client, nsRootFileName, "")
			if err != nil {
				log.Println("[ERROR] RootCertKey addition Failed ", nsRootFileName, err)
				return "", "", "", err
			}
		}
	} else {
		log.Println("[DEBUG] rootCertFile File already added", certFile)
	}
	return "", "", w.dirNames[dirName]["nsRootCertFile"], nil
}

// Run is a thread which will alert whenever files in the directory added for watch gets updated.
func (w *Watcher) Run() {
	for {
		select {
		case event, ok := <-w.watcher.Events:
			if !ok {
				log.Println("[ERROR] Error Watching Events")
				return
			}
			w.watcherMux.Lock()
			log.Println("[DEBUG] event:", event)
			if (event.Op&fsnotify.Remove == fsnotify.Remove) || (event.Op&fsnotify.Write == fsnotify.Write) {
				log.Println("[DEBUG] Folder got Updated", event.Name)
				// strings.Contains(event.Name, "..") this is for mounted certificates
				//strings.Contains(event.Name, ClientCertFile)  for CSR generated
				//if !strings.Contains(event.Name, "..") && !strings.Contains(event.Name, ClientCertFile) {
				if !strings.Contains(event.Name, "..") && !strings.Contains(event.Name, ClientCertChainFile) {
					log.Println("[DEBUG] File not considered for update", event.Name)
				} else {
					uploadFilePath, _ := getDirFileName(event.Name)
					log.Println("UploadFilePath", uploadFilePath)
					if w.dirNames[uploadFilePath]["certFile"] != "" {
						certFile := uploadFilePath + "/" + w.dirNames[uploadFilePath]["certFile"]
						keyFile := uploadFilePath + "/" + w.dirNames[uploadFilePath]["keyFile"]
						log.Println("[DEBUG] upload certFile Path", certFile)
						log.Println("[DEBUG] upload File Path", keyFile)
						if fileExists(certFile) {
							certData, keyData, err := getCertKeyData(certFile, keyFile)
							if err == nil {
								nsCertFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(certData)), 55)
								nsKeyFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(keyData)), 55)
								/* if CertKey and KeyFile did not change then do not update */
								if nsconfigengine.IsCertKeyPresent(w.nsConfig.client, nsCertFileName, nsKeyFileName) == false {
									log.Println("[DEBUG] nsfileName", nsCertFileName, nsKeyFileName)
									nsconfigengine.UploadCertData(w.nsConfig.client, certData, nsCertFileName, keyData, nsKeyFileName)
									rootFileName, err := nsconfigengine.UpdateBindings(w.nsConfig.client, w.dirNames[uploadFilePath]["nsCertFileName"], w.dirNames[uploadFilePath]["nsCertFileName"], nsCertFileName, nsKeyFileName)
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
								log.Println("[DEBUG] nsRootiFileName", nsRootFileName)
								log.Println("[DEBUG] upload certFile Path", certFile)
								var keyData []byte
								nsconfigengine.UploadCertData(w.nsConfig.client, certData, nsRootFileName, keyData, "")
								nsconfigengine.AddCertKey(w.nsConfig.client, nsRootFileName, "")
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
				return
			}
			log.Println("[ERROR] Watcher error:", err)
		}
	}
}
