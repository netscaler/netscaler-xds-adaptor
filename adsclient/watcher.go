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
	"log"
	"os"
	"strings"

	"github.com/fsnotify/fsnotify"
)

// Watcher is for watching certificate directory
type Watcher struct {
	dirNames map[string]map[string]string
	nsConfig *configAdaptor
	watcher  *fsnotify.Watcher
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

//addDir will add the Directory which contains certFile for monitoring, if not already added
//CertFile and KeyFile (optional for rootCert) will be uploaded to Citrix ADC if not previously done.
func (w *Watcher) addDir(certFileName, keyFileName string) error {
	dirName, certFile := getDirFileName(certFileName)
	keyFile := ""
	var ok bool
	if _, ok = w.dirNames[dirName]; !ok {
		err := w.watcher.Add(dirName)
		if err != nil {
			log.Println("[ERROR] Failed to add Directory Name to fsnotify.Watcher:", dirName, err)
			return err
		}
		log.Println("[DEBUG] Directory added for monitoring", dirName)
		w.dirNames[dirName] = make(map[string]string)
	} else {
		log.Println("[DEBUG] Directory already added for monitor", dirName)
	}
	if keyFileName != "" {
		if w.dirNames[dirName]["certFile"] == "" {
			w.dirNames[dirName]["certFile"] = certFile
			log.Println("[DEBUG] Added Certificate File", certFile)
			_, keyFile = getDirFileName(keyFileName)
			w.dirNames[dirName]["keyFile"] = keyFile
			log.Println("[DEBUG] Added Key FIle", keyFile)
			nsCertFile := nsconfigengine.GetSslCertkeyName(certFileName)
			nsKeyFile := nsconfigengine.GetSslCertkeyName(keyFileName) + "_key"
			log.Println("[DEBUG] nsfileName", nsCertFile, nsKeyFile)
			if fileExists(certFileName) {
				nsconfigengine.UploadCert(w.nsConfig.client, certFileName, nsCertFile, keyFileName, nsKeyFile)
			}

		} else {
			log.Println("[DEBUG] CertKey and KeyFile already added", certFile, keyFile)
			return nil
		}
	} else {
		if w.dirNames[dirName]["rootCertFile"] == "" {
			w.dirNames[dirName]["rootCertFile"] = certFile
			log.Println("[DEBUG] Added rootCertFile FIle", certFile)
			nsCertFile := nsconfigengine.GetSslCertkeyName(certFileName)
			log.Println("[DEBUG] nsfileName", nsCertFile)
			if fileExists(certFileName) {
				nsconfigengine.UploadCert(w.nsConfig.client, certFileName, nsCertFile, "", "")
			}

		} else {
			log.Println("[DEBUG] rootCertFile File already added", certFile)
			return nil
		}
	}
	return nil
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
			log.Println("[DEBUG] event:", event)
			if event.Op&fsnotify.Remove == fsnotify.Remove {
				log.Println("[DEBUG] Folder got Updated", event.Name)
				if !strings.Contains(event.Name, "..") {
					log.Println("[DEBUG] Folder not considered for update", event.Name)
				} else {
					uploadFilePath, _ := getDirFileName(event.Name)
					log.Println("UploadFilePath", uploadFilePath)
					if w.dirNames[uploadFilePath]["certFile"] != "" {
						certFile := uploadFilePath + "/" + w.dirNames[uploadFilePath]["certFile"]
						keyFile := uploadFilePath + "/" + w.dirNames[uploadFilePath]["keyFile"]
						log.Println("[DEBUG] upload certFile Path", certFile)
						log.Println("[DEBUG] upload File Path", keyFile)
						nsCertFile := nsconfigengine.GetSslCertkeyName(certFile)
						nsKeyFile := nsconfigengine.GetSslCertkeyName(keyFile) + "_key"
						log.Println("[DEBUG] nsfileName", nsCertFile, nsKeyFile)
						nsconfigengine.DeleteCert(w.nsConfig.client, nsCertFile)
						nsconfigengine.DeleteCert(w.nsConfig.client, nsKeyFile)
						if fileExists(certFile) {
							nsconfigengine.UploadCert(w.nsConfig.client, certFile, nsCertFile, keyFile, nsKeyFile)
							nsconfigengine.UpdateCert(w.nsConfig.client, nsCertFile, nsCertFile, nsKeyFile)
						}
					}
					if w.dirNames[uploadFilePath]["rootCertFile"] != "" {
						certFile := uploadFilePath + "/" + w.dirNames[uploadFilePath]["rootCertFile"]
						log.Println("[DEBUG] upload certFile Path", certFile)
						nsCertFile := nsconfigengine.GetSslCertkeyName(certFile)
						log.Println("[DEBUG] nsfileName", nsCertFile)
						nsconfigengine.DeleteCert(w.nsConfig.client, nsCertFile)
						if fileExists(certFile) {
							nsconfigengine.UploadCert(w.nsConfig.client, certFile, nsCertFile, "", "")
							nsconfigengine.UpdateCert(w.nsConfig.client, nsCertFile, nsCertFile, "")
						}
					}
				}
			}
		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			log.Println("[ERROR] Watcher error:", err)
		}
	}
}
