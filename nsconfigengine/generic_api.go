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

package nsconfigengine

import (
	"log"
	"strconv"

	"github.com/chiradeep/go-nitro/netscaler"
)

// NsConfigEntity respresents a NITRO config to be committed to the Citrix-ADC
type NsConfigEntity struct {
	ResourceType string
	ResourceName string
	Resource     interface{}
	Operation    string
	IgnoreErrors []string
}

// NsConfigCommit commits an array of config entities to the Citrix-ADC
func NsConfigCommit(client *netscaler.NitroClient, configs []NsConfigEntity) error {
	confErr := newNitroError()
	for _, config := range configs {
		operation := "add"
		if config.Operation != "" {
			operation = config.Operation
		}
		confErr.updateError(doNitro(client, nitroConfig{config.ResourceType, config.ResourceName, config.Resource, operation}, config.IgnoreErrors, nil))
	}
	return confErr.getError()
}

// GetNsUptime returns the number of seconds since boot up
func GetNsUptime(client *netscaler.NitroClient) (int, error) {
	var currentUptime int
	uptime, err := client.FindStatWithArgs("nsglobalcntr", "", []string{"counters:sys_cur_duration_sincestart"})
	if err != nil {
		log.Println("[ERROR] Unable to get Uptime beginningStat. ", err)
		return 0, err
	}
	//log.Printf("[TRACE] Duration since start : %v, %s", uptime, uptime["sys_cur_duration_sincestart"].(string))
	currentUptime, err = strconv.Atoi(uptime["sys_cur_duration_sincestart"].(string))
	if err != nil {
		return 0, err
	}
	return currentUptime, nil
}
