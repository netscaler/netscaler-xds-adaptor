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
	"citrix-istio-adaptor/tests/env"
	"errors"
	"fmt"
	"os"
	"testing"
)

func Test_getVserverIP(t *testing.T) {
	testCases := []struct {
		inputVserverIP string
		inputProxyType string
		expectedOutput string
		expecterError  string
	}{
		{"65.1.1.1", "router", "65.1.1.1", ""},
		{"127.0.0.1", "router", "127.0.0.1", ""},
		{"192.145.6.78", "router", "192.145.6.78", ""},
		{"", "router", "nsip", ""},
		{"nsip", "router", "", "Not a valid IP address"},
		{"123.1", "sidecar", "", "Not a valid IP address"},
		{"444", "router", "", "Not a valid IP address"},
		{"fe80:8", "sidecar", "", "Not a valid IP address"},
		{"fe80::90", "router", "", "Not a valid IPv4 address"},
		{"123:1::45", "router", "", "Not a valid IPv4 address"},
	}

	for _, c := range testCases {
		vip, err := getVserverIP(c.inputVserverIP, c.inputProxyType)
		if err == nil && c.expecterError != "" {
			t.Errorf("incorrect evaluation of '%s'/'%s': expected failure '%s', but recevied success", c.inputVserverIP, c.inputProxyType, c.expecterError)
		} else if err != nil && c.expecterError == "" {
			t.Errorf("incorrect evaluation of '%s'/'%s': expected success, but received error '%v'", c.inputVserverIP, c.inputProxyType, err)
		} else if err != nil && err.Error() != c.expecterError {
			t.Errorf("incorrect evaluation of '%s'/'%s': expected error '%v' but got error '%v'", c.inputVserverIP, c.inputProxyType, fmt.Errorf(c.expecterError), err)
		}
		if vip != c.expectedOutput {
			t.Errorf("incorrect evaluation of '%s'/'%s': expected output '%s' but got '%s'", c.inputVserverIP, c.inputProxyType, c.expectedOutput, vip)
		}
	}
}

func Test_getCredentials(t *testing.T) {
	type EI struct {
		userFile string
		passFile string
	}

	type EO struct {
		userName string
		passWord string
		err      string
	}
	t.Log("Unit test of getCredentials func")
	// Set Environment variables for username password
	os.Setenv("NS_USER", "nsroot")
	os.Setenv("NS_PASSWORD", "non-default")
	t.Logf("ENV values: %s %s", os.Getenv("NS_USER"), os.Getenv("NS_PASSWORD"))
	// Create some files
	var fnContent = map[string]string{
		"user1.txt": "user1",
		"pass1.txt": "pass1",
		"user2.txt": "wrong",
		"pass2.txt": "wrong",
	}
	for fn, content := range fnContent {
		err := env.CreateAndWriteFile(fn, content)
		if err != nil {
			t.Fatalf("Could not create file %s. Error: %s", fn, err.Error())
		}
	}

	testCases := []struct {
		input          EI
		expectedOutput EO
	}{
		{EI{"/tmp/userfile", "/tmp/passfile"}, EO{"nsroot", "nsroot", ""}}, //File doesn't exist
		{EI{"", ""}, EO{"nsroot", "non-default", ""}},                      //File not mentioned
		{EI{"user1.txt", "pass1.txt"}, EO{"user1", "pass1", ""}},           //Username and password matches
		{EI{"user2.txt", "pass2.txt"}, EO{"", "", ""}},                     //Expected username/password doesn't match
	}

	for _, c := range testCases {
		userName, passWord, err := getCredentials(c.input.userFile, c.input.passFile)
		if err == nil && len(c.expectedOutput.err) > 0 {
			t.Errorf("inputfile: %s. Expected Error %s but received Success", c.input.userFile, c.expectedOutput.err)
		} else if err != nil && err.Error() != c.expectedOutput.err {
			t.Errorf("inputfile: %s. Expected Error %s but Actual error %v", c.input.userFile, c.expectedOutput.err, err)
		} else if err != nil && len(c.expectedOutput.err) == 0 {
			t.Errorf("inputfile: %s. Expected Success but received error %v", c.input.userFile, err)
		}

		if userName != c.expectedOutput.userName || passWord != c.expectedOutput.passWord {
			t.Logf("inputfile: %s. Expected username: %s. Received Username: %s", c.input.userFile, c.expectedOutput.userName, userName)
		}
		if passWord != c.expectedOutput.passWord {
			t.Logf("inputfile: %s. Expected password: %s. Received password: %s", c.input.userFile, c.expectedOutput.passWord, passWord)
		}
		if userName == c.expectedOutput.userName && passWord == c.expectedOutput.passWord {
			t.Logf("inputfile: %s. Success!", c.input.userFile)
		}
	}
	// Delete files
	for fn := range fnContent {
		err := env.DeleteFile(fn)
		if err != nil {
			t.Errorf("Could not delete file %s. Error: %s", fn, err.Error())
		}
	}
}

func Test_getIstioAdaptorVersion(t *testing.T) {
	// Create file
	content := "1.0.0"
	if err := env.CreateAndWriteFile(versionFile, content); err != nil {
		t.Fatalf("Could not create versionFile. Error: %s", err.Error())
	}
	contentFromFile, err := getIstioAdaptorVersion()
	if err == nil && content != contentFromFile {
		t.Errorf("inputfile: %s. Expected content %s got %s", versionFile, content, contentFromFile)
	}
	// Delete file
	if err := env.DeleteFile("/etc/Version"); err != nil {
		t.Errorf("Could not delete /etc/Version. Error: %s", err.Error())
	}
	contentFromFile, err = getIstioAdaptorVersion()
	er := errors.New("Version File does not exist")
	if er.Error() != err.Error() {
		t.Errorf("Expected Error %v but got %v", er, err)
	}
}
