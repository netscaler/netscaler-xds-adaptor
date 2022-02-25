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

package nsconfigengine

import (
	"crypto/md5"
	"fmt"
	"log"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/hashicorp/go-hclog"

	netscaler "github.com/citrix/adc-nitro-go/service"
)

type nitroError struct {
	errorCount int
	errors     []string
}

var nsconfLogger hclog.Logger

func init() {
	level := hclog.LevelFromString("DEBUG") // Default level
	logLevel, ok := os.LookupEnv("LOGLEVEL")
	if ok {
		lvl := hclog.LevelFromString(logLevel)
		if lvl != hclog.NoLevel {
			level = lvl
		} else {
			log.Printf("LOGLEVEL not set to a valid log level (%s), defaulting to %d", logLevel, level)
		}
	}
	_, jsonLog := os.LookupEnv("JSONLOG")
	nsconfLogger = hclog.New(&hclog.LoggerOptions{
		Name:            "xDS-Adaptor",
		Level:           level,
		Color:           hclog.AutoColor,
		JSONFormat:      jsonLog,
		IncludeLocation: true,
	})
	log.Printf("[INFO] nsconfigengine logger created with loglevel = %s and jsonLog = %v", logLevel, jsonLog)
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
	// These next fields are primarily used for binding/unbinding operations
	boundResourceType string
	boundResourceName string
	bindingFilterName string
}

func attemptLogin(client *netscaler.NitroClient) error {
	var err error
	// Establish session with ADC if not already established.
	for i := 0; i <= 2; i++ { // Try login attempt thrice
		err = client.Login()
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("Login attempts failed : %v", err)
}

func attemptConfig(client *netscaler.NitroClient, resourceType string, resourceName string, resource interface{}, operation, boundResourceType, boundResourceName, bindingFilterName string) error {
	var err error
	if operation == "add" {
		_, err = client.AddResource(resourceType, resourceName, resource)
	} else if operation == "set" {
		if len(resourceName) > 0 {
			_, err = client.UpdateResource(resourceType, resourceName, resource)
		} else {
			err = client.UpdateUnnamedResource(resourceType, resource)
		}
	} else if operation == "delete" {
		if resource != nil {
			err = client.DeleteResourceWithArgsMap(resourceType, resourceName, resource.(map[string]string))
		} else {
			err = client.DeleteResource(resourceType, resourceName)
		}
	} else if operation == "unbind" {
		err = client.UnbindResource(resourceType, resourceName, boundResourceType, boundResourceName, bindingFilterName)
	} else {
		err = client.ActOnResource(resourceType, resource, operation)
	}
	return err
}

func commitConfig(client *netscaler.NitroClient, resourceType string, resourceName string, resource interface{}, operation, boundResourceType, boundResourceName, bindingFilterName string) error {
	var err error

	for i := 0; i < 2; i++ {
		err := attemptLogin(client)
		if err != nil {
			return err
		}
		err = attemptConfig(client, resourceType, resourceName, resource, operation, boundResourceType, boundResourceName, bindingFilterName)
		if err == nil || !strings.Contains(err.Error(), "Not logged in or connection timed out") {
			return err
		}
	}
	return err
}

func doNitro(client *netscaler.NitroClient, nsConfig nitroConfig, ignoreErrors []string, actionsOnError []nitroConfig) error {
	var err error
	err = commitConfig(client, nsConfig.resourceType, nsConfig.resourceName, nsConfig.resource, nsConfig.operation, nsConfig.boundResourceType, nsConfig.boundResourceName, nsConfig.bindingFilterName)
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
			actionErr = commitConfig(client, action.resourceType, action.resourceName, action.resource, action.operation, action.boundResourceType, action.boundResourceName, action.bindingFilterName)
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

// GetNameWithQuotedPeriods returns string with periods quoted with ""
func GetNameWithQuotedPeriod(entityName string) string {
	var re = regexp.MustCompile("[.]")
	name := re.ReplaceAllString(entityName, "\".\"")
	return name
}

// GetNameWithoutPeriod returns string with periods replaced by _
func GetNameWithoutPeriod(entityName string) string {
	var re = regexp.MustCompile("[.]")
	name := re.ReplaceAllString(entityName, "_")
	return name
}

// GetPrefixForGateway returns prefix based on Vserver IP
func GetPrefixForGateway(ipaddress string) string {
	var re = regexp.MustCompile("[.]")
	name := re.ReplaceAllString(ipaddress, "_")
	return "cxa_" + name + "_"
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

// GetNSCompatibleNameHash returns md5 hash for non-empty input
func GetNSCompatibleNameHash(input string, length int) string {
	if input == "" {
		return ""
	}
	md5 := md5.Sum([]byte(input))
	output := GetNSCompatibleName(fmt.Sprintf("%x", md5[:]))
	if !unicode.IsLetter(rune(output[0])) {
		output = "ns_" + output
	}
	if len(output) > length {
		return output[0:length]
	}
	return output
}

// GetNSCompatibleNameByLen returns a name, not greater than length characters long, which is accepted by the config module on the Citrix-ADC
func GetNSCompatibleNameByLen(entityName string, length int) string {
	name := GetNSCompatibleName(entityName)
	if len(name) > length {
		return GetNSCompatibleNameHash(entityName, length)
	}
	return name
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

// GetNsReleaseBuild returns the build details of Citrix ADC
func GetNsReleaseBuild() (float64, float64) {
	return curBuild.release, curBuild.buildNo
}

// SetNsReleaseBuild initializes the release number and version number in nsconfigengine of the Citrix-ADC being configured
func SetNsReleaseBuild(build map[string]interface{}) error {
	var err error
	curBuild.release, curBuild.buildNo, err = getBuildInfo(build)
	nsconfLogger.Info("ADC build info", "build", build, "version", curBuild)
	return err
}

func getBuildInfo(nsVersion map[string]interface{}) (float64, float64, error) {
	re := regexp.MustCompile(`[0-9]+[.]*[[0-9]+]*`) //NS12.1: Build 53.3.nc or NS12.1: Build 53.nc
	submatchall := re.FindAllString(nsVersion["version"].(string), -1)
	if submatchall == nil {
		nsconfLogger.Error("getBuildInfo: Couldn't extract release and build no")
		return 0, 0, fmt.Errorf("[ERROR]: Couldn't extract release and build no")
	}
	release, errR := strconv.ParseFloat(submatchall[0], 64)
	if errR != nil {
		nsconfLogger.Error("getBuildInfo: Failed converting Citrix ADC Release")
		return 0, 0, errR
	}
	buildNo, errB := strconv.ParseFloat(submatchall[1], 64)
	if errB != nil {
		nsconfLogger.Error("getBuildInfo: Failed converting Citrix ADC build no")
		return 0, 0, errB
	}
	return release, buildNo, nil

}

// GetLogString will mask sensitive info
func GetLogString(data interface{}) string {
	s := fmt.Sprintf("%v", data)
	s = strings.Replace(s, "\n", "", -1)
	m1 := regexp.MustCompile("BEGIN CERTIFICATE(.*)END CERTIFICATE")
	s = m1.ReplaceAllString(s, " XXX ")
	m1 = regexp.MustCompile("BEGIN RSA PRIVATE KEY(.*)END RSA PRIVATE KEY")
	s = m1.ReplaceAllString(s, " XXX ")
	m1 = regexp.MustCompile("BEGIN EC PRIVATE KEY(.*)END EC PRIVATE KEY")
	return m1.ReplaceAllString(s, " XXX ")
}

// GetParticularNSField function will return the value for the provided fieldName from the provided resourceType.
// If fieldName doesn't exist in resourceType, then returned value will be nil.
func GetParticularNSField(client *netscaler.NitroClient, resourceType, fieldName string) (interface{}, error) {
	res, err := client.FindResource(resourceType, "")
	//[]map[string]interface{}, error = FindResourceArrayWithParams(findParams FindParams)
	if err != nil {
		nsconfLogger.Error("GetParticularNSField: Could not get fieldName value for resource", "resource", resourceType, "fieldName", fieldName, "error", err)
		return nil, err
	}
	return res[fieldName], nil
}
