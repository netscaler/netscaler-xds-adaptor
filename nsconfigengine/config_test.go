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
	"citrix-istio-adaptor/tests/env"
	"errors"
	"fmt"
	"testing"
)

func init() {
	env.Init()
}

func Test_nitroError(t *testing.T) {
	cases := []struct {
		input          []error
		expectedOutput error
	}{
		{[]error{nil, nil}, nil},
		{[]error{fmt.Errorf("1st error"), nil, fmt.Errorf("2nd error")}, fmt.Errorf("Config application failed with 2 errors - 1st error,2nd error")},
		{[]error{}, nil},
	}
	for _, c := range cases {
		confErr := newNitroError()
		for _, inputErr := range c.input {
			confErr.updateError(inputErr)
		}
		err := confErr.getError()
		failTestCase := false
		if err == nil {
			if c.expectedOutput != nil {
				failTestCase = true
			}
		} else {
			if c.expectedOutput == nil {
				failTestCase = true
			} else if err.Error() != c.expectedOutput.Error() {
				failTestCase = true
			}
		}
		if failTestCase == true {
			t.Errorf("incorrect output for `%v` : expected `%v` but got `%v`", c.input, c.expectedOutput, err)
		}
	}
}

func Test_doNitro(t *testing.T) {
	cases := []struct {
		inputNsConfig       nitroConfig
		inputIgnoreErrors   []string
		inputActionsOnError []nitroConfig
		expectedOutput      error
	}{
		{nitroConfig{"lbvserver", "t1", map[string]interface{}{"name": "t1", "servicetype": "http"}, "add"}, nil, nil, nil},
		{nitroConfig{"lbvserver", "t1", nil, "delete"}, nil, nil, nil},
		{nitroConfig{"lbvserver_service_binding", "t3", map[string]interface{}{"name": "t3", "servicename": "s1"}, "add"}, nil, nil, fmt.Errorf("[ERROR] go-nitro: Failed to create resource of type lbvserver_service_binding, name=t3, err=failed: 404 Not Found ({ \"errorcode\": 258, \"message\": \"No such resource [name, t3]\", \"severity\": \"ERROR\" })")},
		{nitroConfig{"lbvserver_service_binding", "t4", map[string]interface{}{"name": "t4", "servicename": "s1"}, "add"}, []string{"No such resource", "xxx"}, nil, nil},
		{nitroConfig{"lbvserver_service_binding", "t5", map[string]interface{}{"name": "t5", "servicename": "s1"}, "add"}, []string{"xxx"}, []nitroConfig{{"lbvserver", "t3", nil, "delete"}}, nil},
		{nitroConfig{"lbvserver_service_binding", "t6", map[string]interface{}{"name": "t6", "servicename": "s1"}, "add"}, []string{"xxx"}, []nitroConfig{{"lbvserver_service_binding", "t2", map[string]interface{}{"name": "t2", "servicename": "s1"}, "add"}}, fmt.Errorf("[ERROR] go-nitro: Failed to create resource of type lbvserver_service_binding, name=t6, err=failed: 404 Not Found ({ \"errorcode\": 258, \"message\": \"No such resource [name, t6]\", \"severity\": \"ERROR\" }) ; [ERROR] go-nitro: Failed to create resource of type lbvserver_service_binding, name=t2, err=failed: 404 Not Found ({ \"errorcode\": 258, \"message\": \"No such resource [name, t2]\", \"severity\": \"ERROR\" })")},
	}
	client := env.GetNitroClient()
	for _, c := range cases {
		err := doNitro(client, c.inputNsConfig, c.inputIgnoreErrors, c.inputActionsOnError)
		t.Logf("doNitro input - %v ----- output - %v", c, err)
		failTestCase := false
		if err == nil {
			if c.expectedOutput != nil {
				failTestCase = true
			}
		} else {
			if c.expectedOutput == nil {
				failTestCase = true
			} else if err.Error() != c.expectedOutput.Error() {
				failTestCase = true
			}
		}
		if failTestCase == true {
			t.Errorf("incorrect output for `%v` : expected `%v` but got `%v`", c, c.expectedOutput, err)
		}

	}
}

func Test_GetNSCompatibleName(t *testing.T) {
	cases := []struct {
		input          string
		expectedOutput string
	}{
		{"outbound|30-*po|", "outbound_30__po_"},
		{"outbound|15443||istio-egressgateway.istio-system.svc.cluster.local", "outbound_15443__istio_egressgateway_istio_system_svc_cluster_local"},
		{"dummy", "dummy"},
		{"3jd*jdj", "ns_3jd_jdj"},
	}

	for _, c := range cases {
		if output := GetNSCompatibleName(c.input); output != c.expectedOutput {
			t.Errorf("incorrect output for `%s` : expected `%s` but got `%s`", c.input, c.expectedOutput, output)
		}
	}
}

func Test_getValueString(t *testing.T) {
	cases := []struct {
		inputMap      map[string]interface{}
		inputKey      string
		expectedValue string
		expectedError error
	}{
		{map[string]interface{}{"foo": "bar", "fool": "ball", "foot": 1}, "foo", "bar", nil},
		{map[string]interface{}{"foo": "bar", "fool": "ball", "foot": 1}, "fool", "ball", nil},
		{map[string]interface{}{"foo": "bar", "fool": "ball", "foot": 1}, "foot", "", fmt.Errorf("value '1' is of type int and not string")},
		{map[string]interface{}{"foo": "bar", "fool": "ball", "foot": 1}, "fo", "", fmt.Errorf("key 'fo' not found in resource")},
	}
	for _, c := range cases {
		outputStr, err := getValueString(c.inputMap, c.inputKey)
		failTestCase := false
		if outputStr != c.expectedValue {
			failTestCase = true
		} else if err == nil && c.expectedError != nil {
			failTestCase = true
		} else if err != nil && c.expectedError == nil {
			failTestCase = true
		} else if err != nil && c.expectedError != nil && err.Error() != c.expectedError.Error() {
			failTestCase = true
		}
		if failTestCase == true {
			t.Errorf("incorrect output for %v/%s : expected (%s,%v) but got (%s,%v)", c.inputMap, c.inputKey, c.expectedValue, c.expectedError, outputStr, err)
		}
	}
}

func Test_getValueInt(t *testing.T) {
	cases := []struct {
		inputMap      map[string]interface{}
		inputKey      string
		expectedValue int
		expectedError error
	}{
		{map[string]interface{}{"foo": 123, "fool": "ball", "foot": 1}, "foo", 123, nil},
		{map[string]interface{}{"foo": "bar", "fool": "ball", "foot": 1}, "foo", 0, fmt.Errorf("Cannot convert value 'bar' to integer - strconv.Atoi: parsing \"bar\": invalid syntax")},
		{map[string]interface{}{"foo": "bar", "fool": "456", "foot": 1}, "fool", 456, nil},
		{map[string]interface{}{"foo": "bar", "fool": "ball", "foot": true}, "foot", 0, fmt.Errorf("value 'true' is of type bool and not int")},
		{map[string]interface{}{"foo": "bar", "fool": "ball", "foot": 1}, "fo", 0, fmt.Errorf("key 'fo' not found in resource")},
	}
	for _, c := range cases {
		outputStr, err := getValueInt(c.inputMap, c.inputKey)
		failTestCase := false
		if outputStr != c.expectedValue {
			failTestCase = true
		} else if err == nil && c.expectedError != nil {
			failTestCase = true
		} else if err != nil && c.expectedError == nil {
			failTestCase = true
		} else if err != nil && c.expectedError != nil && err.Error() != c.expectedError.Error() {
			failTestCase = true
		}
		if failTestCase == true {
			t.Errorf("incorrect output for %v/%s : expected (%d,%v) but got (%d,%v)", c.inputMap, c.inputKey, c.expectedValue, c.expectedError, outputStr, err)
		}
	}

}

func Test_getBuildInfo(t *testing.T) {
	cases := []struct {
		input           map[string]interface{}
		expectedRelease float64
		expectedBuild   float64
	}{
		{map[string]interface{}{"installedversion": false, "mode": 0, "version": "NetScaler NS12.1: Build 53.3.nc, Date: Jun 17 2019, 22:47:58   (64-bit)"}, 12.1, 53.3},
		{map[string]interface{}{"installedversion": false, "mode": 0, "version": "NetScaler NS12.1: Build 53.nc, Date: Jun 17 2019, 22:47:58   (64-bit)"}, 12.1, 53},
		{map[string]interface{}{"installedversion": false, "mode": 0, "version": "NetScaler NSabc: Build xyz.nc, Date: Jun"}, 0, 0},
	}

	for _, c := range cases {
		release, build, err := getBuildInfo(c.input)
		if build == 0 {
			er := errors.New("[ERROR]: Couldn't Extract Release and Build No")
			if er.Error() != err.Error() {
				t.Errorf("Incorrect Error: Got %v, Expected %v", err, er)
			}
		}
		if build != 0 && (build != c.expectedBuild || release != c.expectedRelease) {
			t.Errorf("Incorrect output for `%v` : expected Release=%f buildNo=%f but got `Release=%f and buildNo=%f`", c.input, c.expectedRelease, c.expectedBuild, release, build)
		}
	}
}
