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

package adsclient

import (
	"citrix-istio-adaptor/tests/env"
	"github.com/chiradeep/go-nitro/netscaler"
	"log"
	"strings"
	"testing"
)

func init() {
	env.Init()
}

func verifyFeatures(t *testing.T, client *netscaler.NitroClient, features []string) {
	found := 0
	result, err := client.ListEnabledFeatures()
	if err != nil {
		t.Error("Failed to retrieve features", err)
		log.Println("Cannot continue")
		return
	}
	for _, f := range features {
		for _, r := range result {
			if strings.EqualFold(f, r) {
				found = found + 1
			}
		}
	}
	if found != len(features) {
		t.Error("Requested features do not match enabled features=", features, "result=", result)
	}
}

func verifyModes(t *testing.T, client *netscaler.NitroClient, modes []string) {
	found := 0
	result, err := client.ListEnabledModes()
	if err != nil {
		t.Error("Failed to retrieve modes", err)
		log.Println("Cannot continue")
		return
	}
	for _, m := range modes {
		for _, r := range result {
			if strings.EqualFold(m, r) {
				found = found + 1
			}
		}
	}
	if found != len(modes) {
		t.Error("Requested modes do not match enabled modes=", modes, "result=", result)
	}
}

func Test_bootstrapConfig(t *testing.T) {
	t.Log("Verify BootStrap Config")
	var err interface{}
	configAd, err := newConfigAdaptor(env.GetNetscalerURL(), env.GetNetscalerUser(), env.GetNetscalerPassword(), "15010", "", "k8s", "", "ns-logproxy.citrix-system")
	if err != nil {
		t.Errorf("Unable to get a config adaptor. newConfigAdaptor failed with %v", err)
	}
	if strings.Contains(env.GetNetscalerURL(), "localhost") || strings.Contains(env.GetNetscalerURL(), "127.0.0.1") {
		t.Logf("Verifying sidecar bootstrap config")
		configs := []env.VerifyNitroConfig{
			{"service", "dns_service", map[string]interface{}{"name": "dns_service", "port": 53, "servicetype": "DNS", "healthmonitor": "NO"}},
			{"lbvserver", "dns_vserver", map[string]interface{}{"name": "dns_vserver", "servicetype": "DNS"}},
			{netscaler.Lbvserver_service_binding.Type(), "dns_vserver", map[string]interface{}{"name": "dns_vserver", "servicename": "dns_service"}},
			{"dnsnameserver", "dns_vserver", map[string]interface{}{"dnsvservername": "dns_vserver"}},
			{"nsacl", "allowpromexp", map[string]interface{}{"aclname": "allowpromexp", "aclaction": "ALLOW", "protocol": "TCP", "destportval": "8888", "priority": 65536, "kernelstate": "APPLIED"}},
			{"nsacl", "denyall", map[string]interface{}{"aclname": "denyall", "aclaction": "DENY", "priority": 100000, "kernelstate": "APPLIED"}},
			{"lbvserver", "drop_all_vserver", map[string]interface{}{"name": "drop_all_vserver", "servicetype": "ANY", "ipv46": "*", "port": 65535, "listenpolicy": "CLIENT.TCP.DSTPORT.NE(15010)"}},
		}
		err = env.VerifyConfigBlockPresence(configAd.client, configs)
		if err != nil {
			t.Errorf("Config verification failed for sidecar bootstrap config, error %v", err)
		}
	}
	t.Log("Verify Features Applied")
	features := []string{"SSL", "LB", "CS", "REWRITE", "RESPONDER", "APPFLOW"}
	verifyFeatures(t, configAd.client, features)
	t.Log("Verify Modes Applied")
	modes := []string{"ULFD"}
	verifyModes(t, configAd.client, modes)
	t.Log("Verify bootstrap config")
	configs := []env.VerifyNitroConfig{
		{netscaler.Nstcpprofile.Type(), "nstcp_default_profile", map[string]interface{}{"name": "nstcp_default_profile", "mss": 1410}},
		{netscaler.Nstcpprofile.Type(), "nstcp_internal_apps", map[string]interface{}{"name": "nstcp_internal_apps", "mss": 1410}},
		{netscaler.Nstcpprofile.Type(), "nsulfd_default_profile", map[string]interface{}{"name": "nsulfd_default_profile", "mss": 1410}},
		{netscaler.Nshttpprofile.Type(), "nshttp_default_profile", map[string]interface{}{"name": "nshttp_default_profile", "http2": "ENABLED", "http2maxconcurrentstreams": 1000}},
		{netscaler.Responderaction.Type(), "return404", map[string]interface{}{"name": "return404", "type": "respondwith", "target": "\"HTTP/1.1 404 Not found\r\n\r\n\""}},
		{netscaler.Responderpolicy.Type(), "return404", map[string]interface{}{"name": "return404", "rule": "true", "action": "return404"}},
		{netscaler.Lbvserver.Type(), "ns_blackhole_http", map[string]interface{}{"name": "ns_blackhole_http", "servicetype": "HTTP"}},
		{netscaler.Service.Type(), "ns_blackhole_http", map[string]interface{}{"name": "ns_blackhole_http", "servername": "127.0.0.1", "port": 1, "servicetype": "HTTP", "healthmonitor": "NO"}},
		{netscaler.Lbvserver_service_binding.Type(), "ns_blackhole_http", map[string]interface{}{"name": "ns_blackhole_http", "servicename": "ns_blackhole_http"}},
		{netscaler.Lbvserver_responderpolicy_binding.Type(), "ns_blackhole_http", map[string]interface{}{"name": "ns_blackhole_http", "policyname": "return404", "priority": 1}},
		{netscaler.Lbvserver.Type(), "ns_dummy_http", map[string]interface{}{"name": "ns_dummy_http", "servicetype": "HTTP"}},
		{netscaler.Lbvserver_service_binding.Type(), "ns_dummy_http", map[string]interface{}{"name": "ns_dummy_http", "servicename": "ns_blackhole_http"}},
	}
	err = env.VerifyConfigBlockPresence(configAd.client, configs)
	if err != nil {
		t.Errorf("Config verification failed for bootstrap config, error %v", err)
	}
	t.Log("Verify logproxy/appflow related config")
	configs = []env.VerifyNitroConfig{
		{netscaler.Appflowparam.Type(), "", map[string]interface{}{"templaterefresh": 60, "securityinsightrecordinterval": 60, "httpurl": "ENABLED", "httpcookie": "ENABLED", "httpreferer": "ENABLED", "httpmethod": "ENABLED", "httphost": "ENABLED", "httpuseragent": "ENABLED", "httpcontenttype": "ENABLED", "securityinsighttraffic": "ENABLED", "httpquerywithurl": "ENABLED", "urlcategory": "ENABLED", "distributedtracing": "ENABLED", "disttracingsamplingrate": 100}},
		{"analyticsprofile", "ns_analytics_default_http_profile", map[string]interface{}{"name": "ns_analytics_default_http_profile", "type": "webinsight", "httpurl": "ENABLED", "httpmethod": "ENABLED", "httphost": "ENABLED", "httpuseragent": "ENABLED", "urlcategory": "ENABLED", "httpcontenttype": "ENABLED", "httpvia": "ENABLED", "httpdomainname": "ENABLED", "httpurlquery": "ENABLED"}},
		{"analyticsprofile", "ns_analytics_default_tcp_profile", map[string]interface{}{"name": "ns_analytics_default_tcp_profile", "type": "tcpinsight"}},
	}
	err = env.VerifyConfigBlockPresence(configAd.client, configs)
	if err != nil {
		t.Errorf("Config verification failed for logproxy config, error %v", err)
	}
}
