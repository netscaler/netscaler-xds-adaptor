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

package env

import (
	"fmt"
	netscaler "github.com/citrix/adc-nitro-go/service"
	"log"
	"reflect"
)

type VerifyNitroConfig struct {
	ResourceType string
	ResourceName string
	Resource     map[string]interface{}
}

func VerifyConfigBlockPresence(client *netscaler.NitroClient, configs []VerifyNitroConfig) error {
	for _, config := range configs {
		resource, err := client.FindResource(config.ResourceType, config.ResourceName)
		if err != nil {
			return err
		}
		err = verifyResourceSame(config.Resource, resource)
		if err != nil {
			return fmt.Errorf("%s/%s - %s", config.ResourceType, config.ResourceName, err.Error())
		}
	}
	log.Printf("VerifyConfigBlock succeeded for %s", configs)
	return nil
}

func VerifyNotPresent(client *netscaler.NitroClient, config VerifyNitroConfig) error {
	if client.ResourceExists(config.ResourceType, config.ResourceName) == true {
		return fmt.Errorf("Resource %s/%s present on system - should not exist", config.ResourceType, config.ResourceName)
	}
	return nil
}

func VerifyConfigBlockAbsence(client *netscaler.NitroClient, configs []VerifyNitroConfig) error {
	for _, config := range configs {
		err := VerifyNotPresent(client, config)
		if err != nil {
			return err
		}
	}
	log.Printf("VerifyConfigBlockAbsence succeeded for %s", configs)
	return nil
}

func verifyResourceSame(item1 map[string]interface{}, item2 map[string]interface{}) error {
	for keyItem1, valItem1 := range item1 {
		valItem2, ok := item2[keyItem1]
		if !ok {
			return fmt.Errorf("key '%s' of %v not present in %v", keyItem1, item1, item2)
		}
		if reflect.TypeOf(valItem1).String() == "int" {
			valItem1 = fmt.Sprintf("%v", valItem1)
		}
		if reflect.TypeOf(valItem2).String() == "float64" || reflect.TypeOf(valItem2).String() == "int" {
			valItem2 = fmt.Sprintf("%v", valItem2)
		}
		if reflect.DeepEqual(valItem1, valItem2) == false {
			return fmt.Errorf("expected value %s('%v') and fethed value %s('%v') differ for key '%s'", reflect.TypeOf(valItem1).String(), valItem1, reflect.TypeOf(valItem2).String(), valItem2, keyItem1)
		}
	}
	return nil
}

func VerifyBindings(client *netscaler.NitroClient, resourceType string, resourceName string, boundResourceType string, expected []map[string]interface{}) error {
	bindings, err := client.FindAllBoundResources(resourceType, resourceName, boundResourceType)
	if err != nil {
		return err
	}
	if len(bindings) != len(expected) {
		return fmt.Errorf("Mismatch in number of bindings - received : %d   expected : %d", len(bindings), len(expected))
	}
	for _, exp := range expected {
		found := false
		for _, binding := range bindings {
			err = verifyResourceSame(exp, binding)
			if err == nil {
				found = true
				break
			}
		}
		if found == false {
			return fmt.Errorf("Could not find expected binding %v in fetched bindings %v", exp, bindings)
		}
	}
	return nil
}
