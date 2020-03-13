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
	"fmt"
	"log"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/chiradeep/go-nitro/netscaler"
)

const cpxHttpdPort = 80

type nitroError struct {
	errorCount int
	errors     []string
}

func newNitroError() *nitroError {
	err := new(nitroError)
	err.errors = make([]string, 0)
	return err
}

func (nitroErr *nitroError) updateError(err error) {
	if err != nil {
		nitroErr.errorCount++
		nitroErr.errors = append(nitroErr.errors, err.Error())
	}
}

func (nitroErr *nitroError) getError() error {
	if nitroErr.errorCount != 0 {
		return fmt.Errorf("Config application failed with %d errors - %v", nitroErr.errorCount, strings.Join(nitroErr.errors, ","))
	}
	return nil
}

type nitroConfig struct {
	resourceType string
	resourceName string
	resource     interface{}
	operation    string
}

func commitConfig(client *netscaler.NitroClient, resourceType string, resourceName string, resource interface{}, operation string) error {
	var err error
	// Establish session with ADC if not already established.
	for i := 0; i <= 2; i++ { // Try login attempt thrice
		err = client.Login()
		if err == nil { // Login successful
			break
		} else if i == 2 {
			log.Printf("[DEBUG]: Token based Login is not successful!")
		}
	}

	if operation == "add" {
		_, err = client.AddResource(resourceType, resourceName, resource)
	} else if operation == "set" {
		_, err = client.UpdateResource(resourceType, resourceName, resource)
	} else if operation == "delete" {
		if resource != nil {
			err = client.DeleteResourceWithArgsMap(resourceType, resourceName, resource.(map[string]string))
		} else {
			err = client.DeleteResource(resourceType, resourceName)
		}
	} else {
		err = client.ActOnResource(resourceType, resource, operation)
	}
	return err
}

func doNitro(client *netscaler.NitroClient, nsConfig nitroConfig, ignoreErrors []string, actionsOnError []nitroConfig) error {
	var err error
	err = commitConfig(client, nsConfig.resourceType, nsConfig.resourceName, nsConfig.resource, nsConfig.operation)
	if err != nil {
		for _, errMessage := range ignoreErrors {
			if strings.Contains(err.Error(), errMessage) {
				err = nil
				break
			}
		}
	}
	if err != nil && actionsOnError != nil {
		var actionErr error
		errStr := ""
		for _, action := range actionsOnError {
			actionErr = commitConfig(client, action.resourceType, action.resourceName, action.resource, action.operation)
			if actionErr != nil {
				errStr = errStr + "; " + actionErr.Error()
			}
		}
		if errStr != "" {
			return fmt.Errorf(err.Error() + " " + errStr)
		}
		return nil
	}
	return err
}

// GetNSCompatibleName returns a name which is accepted by the config module on the Citrix-ADC
func GetNSCompatibleName(entityName string) string {
	var re = regexp.MustCompile("[-.|!*/]")
	name := re.ReplaceAllString(entityName, "_")
	if unicode.IsLetter(rune(name[0])) {
		return name
	}
	return "ns_" + re.ReplaceAllString(entityName, "_")
}

func getValueString(obj map[string]interface{}, name string) (string, error) {
	if valI, ok := obj[name]; ok {
		if val, ok1 := valI.(string); ok1 {
			return val, nil
		}
		return "", fmt.Errorf("value '%v' is of type %s and not string", valI, reflect.TypeOf(valI).String())
	}
	return "", fmt.Errorf("key '%s' not found in resource", name)
}

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

type buildInfo struct {
	release, buildNo float64
}

var curBuild buildInfo

func getNsReleaseBuild() (float64, float64) {
	return curBuild.release, curBuild.buildNo
}

// SetNsReleaseBuild initializes the release number and version number in nsconfigengine of the Citrix-ADC being configured
func SetNsReleaseBuild(build map[string]interface{}) error {
	var err error
	curBuild.release, curBuild.buildNo, err = getBuildInfo(build)
	log.Printf("NsBuild %v %v", build, curBuild)
	return err
}

func getBuildInfo(nsVersion map[string]interface{}) (float64, float64, error) {
	re := regexp.MustCompile(`[0-9]+[.]*[[0-9]+]*`) //NS12.1: Build 53.3.nc or NS12.1: Build 53.nc
	submatchall := re.FindAllString(nsVersion["version"].(string), -1)
	if submatchall == nil {
		log.Printf("[ERROR]: Couldn't Extract Release and Build No")
		return 0, 0, fmt.Errorf("[ERROR]: Couldn't Extract Release and Build No")
	}
	release, errR := strconv.ParseFloat(submatchall[0], 64)
	if errR != nil {
		log.Printf("[ERROR]: Failed converting Citrix ADC Release")
		return 0, 0, errR
	}
	buildNo, errB := strconv.ParseFloat(submatchall[1], 64)
	if errB != nil {
		log.Printf("[ERROR]: Failed converting Citrix ADC BuildNo")
		return 0, 0, errB
	}
	return release, buildNo, nil

}
