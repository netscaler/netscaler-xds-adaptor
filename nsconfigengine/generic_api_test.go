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
	"testing"

	"github.com/citrix/citrix-xds-adaptor/tests/env"
)

func Test_NsConfigEntity(t *testing.T) {
	client := env.GetNitroClient()
	configs := []NsConfigEntity{
		{ResourceType: "lbvserver", ResourceName: "lbv1", Resource: map[string]interface{}{"name": "lbv1", "servicetype": "http"}},
		{ResourceType: "service", ResourceName: "svc1", Resource: map[string]interface{}{"name": "svc1", "servicetype": "http", "ip": "1.1.1.1", "port": 80}},
		{ResourceType: "lbvserver_service_binding", ResourceName: "lbv1", Resource: map[string]interface{}{"name": "lbv1", "servicename": "svc1"}},
		{ResourceType: "lbvserver_service_binding", ResourceName: "lbv1", Resource: map[string]interface{}{"name": "lbv1", "servicename": "svc1"}, IgnoreErrors: []string{"Resource already exists"}},
		{ResourceType: "service", ResourceName: "svc1", Resource: nil, Operation: "delete"},
		{ResourceType: "lbvserver", ResourceName: "lbv1", Resource: nil, Operation: "delete"},
	}
	err := NsConfigCommit(client, configs)
	if err != nil {
		t.Errorf("NsConfigCommit expected success, but returned %v", err)
	}
}
