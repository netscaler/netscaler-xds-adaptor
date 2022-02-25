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

func Test_getLbMonName(t *testing.T) {
	testCases := []struct {
		input          string
		expectedOutput string
	}{
		{"outbound_4040_v1_httpserverbigbigname_istio130_svc_cluster_local", "v1_httpserverbigbigname_istio130_lbmon"},
		{"outbound_4040__httpserverbigbigname_istio130_svc_cluster_local", "_httpserverbigbigname_istio130_lbmon"},
		{"outbound___httpserverbigbigname_istio130_svc_cluster_local", "_httpserverbigbigname_istio130_lbmon"},
		{"outbound_4040_v1_httpserver_istio130_svc_cluster_local", "outbound_4040_v1_httpserver_istio130_svc_cluster_local_lbmon"},
	}

	for _, c := range testCases {
		output := getLbMonName(c.input)
		if output != c.expectedOutput {
			t.Errorf("FAILED!!! Expected: %s. Received: %s", c.expectedOutput, output)
		} else {
			t.Logf("PASSED for %s\n", c.input)
		}
	}
}

func Test_convertTimeUnits(t *testing.T) {
	type EI struct {
		time int
		unit string
	}
	type EO EI

	testCases := []struct {
		input          EI
		expectedOutput EO
	}{
		{EI{0, "MSEC"}, EO{defaultInterval, "SEC"}},
		{EI{10000, ""}, EO{defaultInterval, "SEC"}},
		{EI{20000, "MSEC"}, EO{20000, "MSEC"}},
		{EI{20940, "MSEC"}, EO{20940, "MSEC"}},
		{EI{20941, "MSEC"}, EO{20, "SEC"}},
		{EI{20941000, "MSEC"}, EO{349, "MIN"}},
		{EI{1506000000, "MSEC"}, EO{20940, "MIN"}},
		{EI{20940, "SEC"}, EO{20940, "SEC"}},
		{EI{26000, "SEC"}, EO{433, "MIN"}},
		{EI{2600, "SEC"}, EO{2600, "SEC"}},
		{EI{26, "MIN"}, EO{26, "MIN"}},
		{EI{26000, "MIN"}, EO{20940, "MIN"}},
	}

	for _, c := range testCases {
		time, unit := convertTimeUnits(c.input.time, c.input.unit, maxInterval, defaultInterval)
		if time != c.expectedOutput.time || unit != c.expectedOutput.unit {
			t.Errorf("FAILED!!! Expected: %d %s. Received: %d %s", c.expectedOutput.time, c.expectedOutput.unit, time, unit)
		} else {
			t.Logf("PASSED for %v\n", c)
		}
	}

}

func Test_LBApi_http(t *testing.T) {
	lbObj := NewLBApi("lbent1", "HTTP", "HTTP", "ROUNDROBIN")
	lbObj.MaxConnections = 200
	lbObj.MaxHTTP2ConcurrentStreams = 300
	lbObj.MaxRequestsPerConnection = 50
	lbObj.LbMonitorObj = new(LBMonitor)
	lbObj.LbMonitorObj.Retries = 7
	lbObj.LbMonitorObj.Interval = 3
	lbObj.LbMonitorObj.IntervalUnits = "SEC"
	lbObj.LbMonitorObj.DownTime = 10
	lbObj.LbMonitorObj.DownTimeUnits = "SEC"
	client := env.GetNitroClient()
	t.Logf("Test LBApi.Add")
	err := lbObj.Add(client)
	if err != nil {
		t.Errorf("LBApi add failed with %v", err)
	}
	configs := []env.VerifyNitroConfig{
		{"lbvserver", "lbent1", map[string]interface{}{"name": "lbent1", "servicetype": "HTTP"}},
		{"nshttpprofile", "nshttp_profile_300", map[string]interface{}{"name": "nshttp_profile_300", "http2": "ENABLED", "http2maxconcurrentstreams": 300}},
		{"servicegroup", "lbent1", map[string]interface{}{"servicegroupname": "lbent1", "servicetype": "HTTP", "maxclient": 200, "maxreq": 50, "httpprofilename": "nshttp_profile_300"}},
		{"lbvserver_servicegroup_binding", "lbent1", map[string]interface{}{"name": "lbent1", "servicegroupname": "lbent1"}},
		{"lbmonitor", "lbent1_lbmon", map[string]interface{}{"monitorname": "lbent1_lbmon", "type": "HTTP-INLINE", "action": "DOWN", "respcode": []interface{}{"200"}, "httprequest": "HEAD /", "retries": 7, "interval": 3, "downtime": 10}},
		{"servicegroup_lbmonitor_binding", "lbent1", map[string]interface{}{"servicegroupname": "lbent1", "monitor_name": "lbent1_lbmon"}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Add %v, error %v", "lbent1", err)
	}
	t.Logf("Test LBApi update")
	lbObj.MaxConnections = 100
	lbObj.MaxRequestsPerConnection = 0
	lbObj.MaxHTTP2ConcurrentStreams = 0
	lbObj.LbMonitorObj.Retries = 0
	lbObj.LbMonitorObj.Interval = 5
	lbObj.LbMonitorObj.IntervalUnits = "SEC"
	lbObj.LbMonitorObj.DownTime = 0
	err = lbObj.Add(client)
	if err != nil {
		t.Errorf("LBApi add failed with %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"lbvserver", "lbent1", map[string]interface{}{"name": "lbent1", "servicetype": "HTTP"}},
		{"servicegroup", "lbent1", map[string]interface{}{"servicegroupname": "lbent1", "servicetype": "HTTP", "maxclient": 100, "maxreq": 0}},
		{"lbvserver_servicegroup_binding", "lbent1", map[string]interface{}{"name": "lbent1", "servicegroupname": "lbent1"}},
		{"lbmonitor", "lbent1_lbmon", map[string]interface{}{"monitorname": "lbent1_lbmon", "type": "HTTP-INLINE", "action": "DOWN", "respcode": []interface{}{"200"}, "httprequest": "HEAD /", "retries": defaultRetries, "interval": 5, "downtime": defaultDownTime}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Update %v, error %v", "lbent1", err)
	}

	t.Logf("Test LBApi update with LB Monitor removal")
	lbObj.LbMonitorObj = nil
	lbObj.MaxConnections = 100
	lbObj.MaxRequestsPerConnection = 0
	lbObj.MaxHTTP2ConcurrentStreams = 0
	err = lbObj.Add(client)
	if err != nil {
		t.Errorf("LBApi add failed with %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"lbvserver", "lbent1", map[string]interface{}{"name": "lbent1", "servicetype": "HTTP"}},
		{"servicegroup", "lbent1", map[string]interface{}{"servicegroupname": "lbent1", "servicetype": "HTTP", "maxclient": 100, "maxreq": 0}},
		{"lbvserver_servicegroup_binding", "lbent1", map[string]interface{}{"name": "lbent1", "servicegroupname": "lbent1"}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Update with LB Monitor removal %v, error %v", "lbent1", err)
	}
	t.Logf("Test LBApi delete")
	err = lbObj.Delete(client)
	if err != nil {
		t.Errorf("LBApi delete failed with %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"lbvserver", "lbent1", map[string]interface{}{"name": "lbent1", "servicetype": "HTTP"}},
		{"servicegroup", "lbent1", map[string]interface{}{"servicegroupname": "lbent1", "servicetype": "HTTP", "maxclient": 100, "maxreq": 0, "httpprofilename": "http_default_profile"}},
		{"lbmonitor", "lbent1_lbmon", map[string]interface{}{"monitorname": "lbent1_lbmon", "type": "HTTP-INLINE", "action": "DOWN", "respcode": []int{200}, "httprequest": "HEAD /", "retries": 5, "interval": 5, "downtime": 10}},
	}
	err = env.VerifyConfigBlockAbsence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Delete %v, error %v", "lbent1", err)
	}
}

func Test_LBApi_tcp(t *testing.T) {
	lbObj := NewLBApi("lbent2", "TCP", "TCP", "LEASTCONNECTION")
	lbObj.MaxConnections = 100
	lbObj.MaxRequestsPerConnection = 25
	client := env.GetNitroClient()
	t.Logf("Test LBApi.Add")
	err := lbObj.Add(client)
	if err != nil {
		t.Errorf("LBApi add failed with %v", err)
	}
	configs := []env.VerifyNitroConfig{
		{"lbvserver", "lbent2", map[string]interface{}{"name": "lbent2", "servicetype": "TCP"}},
		{"servicegroup", "lbent2", map[string]interface{}{"servicegroupname": "lbent2", "servicetype": "TCP", "maxclient": 100, "maxreq": 25}},
		{"lbvserver_servicegroup_binding", "lbent2", map[string]interface{}{"name": "lbent2", "servicegroupname": "lbent2"}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Add %v, error %v", "lbent2", err)
	}
	t.Logf("Test LBApi update")
	lbObj.MaxConnections = 0
	lbObj.MaxRequestsPerConnection = 100
	lbObj.MaxHTTP2ConcurrentStreams = 0
	err = lbObj.Add(client)
	if err != nil {
		t.Errorf("LBApi add failed with %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"lbvserver", "lbent2", map[string]interface{}{"name": "lbent2", "servicetype": "TCP"}},
		{"servicegroup", "lbent2", map[string]interface{}{"servicegroupname": "lbent2", "servicetype": "TCP", "maxclient": 0, "maxreq": 100}},
		{"lbvserver_servicegroup_binding", "lbent2", map[string]interface{}{"name": "lbent2", "servicegroupname": "lbent2"}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Update %v, error %v", "lbent1", err)
	}
	t.Logf("Test LBApi delete")
	err = lbObj.Delete(client)
	if err != nil {
		t.Errorf("LBApi delete failed with %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"lbvserver", "lbent2", map[string]interface{}{"name": "lbent2", "servicetype": "TCP"}},
		{"servicegroup", "lbent2", map[string]interface{}{"servicegroupname": "lbent2", "servicetype": "TCP"}},
	}
	err = env.VerifyConfigBlockAbsence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Delete %v, error %v", "lbent2", err)
	}
}

func Test_LBApi_http_tls(t *testing.T) {
	lbObj := NewLBApi("lbent1s", "HTTP", "SSL", "ROUNDROBIN")
	lbObj.MaxConnections = 200
	lbObj.MaxHTTP2ConcurrentStreams = 300
	lbObj.MaxRequestsPerConnection = 50
	lbObj.LbMonitorObj = new(LBMonitor)
	lbObj.LbMonitorObj.Retries = 7
	lbObj.LbMonitorObj.Interval = 3
	lbObj.LbMonitorObj.IntervalUnits = "SEC"
	lbObj.LbMonitorObj.DownTime = 10
	lbObj.LbMonitorObj.DownTimeUnits = "SEC"
	lbObj.BackendTLS = []SSLSpec{{CertFilename: "certssvc1_svc1", PrivateKeyFilename: "certssvc1_svc1_key", RootCertFilename: "certssvc1_rootCA"}}
	//lbObj.BackendTLS = []SSLSpec{{CertFilename: "../tests/certs/certssvc1/svc1.citrixrootdummy1.com.crt", PrivateKeyFilename: "../tests/certs/certssvc1/svc1.citrixrootdummy1.com.key", RootCertFilename: "../tests/certs/certssvc1/rootCA.crt"}}
	client := env.GetNitroClient()
	UploadCert(client, "../tests/certs/certssvc1/svc1.citrixrootdummy1.com.crt", "certssvc1_svc1", "../tests/certs/certssvc1/svc1.citrixrootdummy1.com.key", "certssvc1_svc1_key")
	UploadCert(client, "../tests/certs/certssvc1/rootCA.crt", "certssvc1_rootCA", "", "")
	t.Logf("Test LBApi.Add")
	err := lbObj.Add(client)
	if err != nil {
		t.Errorf("LBApi add failed with %v", err)
	}
	configs := []env.VerifyNitroConfig{
		{"lbvserver", "lbent1s", map[string]interface{}{"name": "lbent1s", "servicetype": "HTTP"}},
		{"nshttpprofile", "nshttp_profile_300", map[string]interface{}{"name": "nshttp_profile_300", "http2": "ENABLED", "http2maxconcurrentstreams": 300}},
		{"servicegroup", "lbent1s", map[string]interface{}{"servicegroupname": "lbent1s", "servicetype": "SSL", "maxclient": 200, "maxreq": 50}},
		{"lbvserver_servicegroup_binding", "lbent1s", map[string]interface{}{"name": "lbent1s", "servicegroupname": "lbent1s"}},
		{"lbmonitor", "lbent1s_lbmon", map[string]interface{}{"monitorname": "lbent1s_lbmon", "type": "HTTP-INLINE", "action": "DOWN", "respcode": []interface{}{"200"}, "httprequest": "HEAD /", "retries": 7, "interval": 3, "downtime": 10}},
		{"servicegroup_lbmonitor_binding", "lbent1s", map[string]interface{}{"servicegroupname": "lbent1s", "monitor_name": "lbent1s_lbmon"}},
		{"sslcertkey", "certssvc1_svc1", map[string]interface{}{"cert": "/nsconfig/ssl/certssvc1_svc1", "certkey": "certssvc1_svc1", "key": "/nsconfig/ssl/certssvc1_svc1_key"}},
		{"sslcertkey", "certssvc1_rootCA", map[string]interface{}{"cert": "/nsconfig/ssl/certssvc1_rootCA", "certkey": "certssvc1_rootCA"}},
		{"sslservicegroup", "lbent1s", map[string]interface{}{"serverauth": "ENABLED", "servicegroupname": "lbent1s"}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Add %v, error %v", "lbent1s", err)
	}
	err = env.VerifyBindings(client, "sslservicegroup", "lbent1s", "sslcertkey", []map[string]interface{}{{"ca": true, "certkeyname": "certssvc1_rootCA", "servicegroupname": "lbent1s"}, {"certkeyname": "certssvc1_svc1", "servicegroupname": "lbent1s"}})
	if err != nil {
		t.Errorf("Config verification failed for Add binding %v, error %v", "lbent1s", err)
	}
	t.Logf("Test LBApi delete")
	err = lbObj.Delete(client)
	if err != nil {
		t.Errorf("LBApi delete failed with %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"lbvserver", "lbent1s", map[string]interface{}{"name": "lbent1s", "servicetype": "SSL"}},
		{"servicegroup", "lbent1s", map[string]interface{}{"servicegroupname": "lbent1s", "servicetype": "HTTP"}},
		{"lbmonitor", "lbent1s_lbmon", map[string]interface{}{"monitorname": "lbent1s_lbmon", "type": "HTTP-INLINE", "action": "DOWN", "respcode": []int{200}, "httprequest": "HEAD /", "retries": 7, "interval": 3, "downtime": 10}},
	}
	err = env.VerifyConfigBlockAbsence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Delete %v, error %v", "lbent1s", err)
	}
}

func Test_LBApi_tcp_to_http(t *testing.T) {
	lbObj := NewLBApi("lb1", "TCP", "TCP", "ROUNDROBIN")
	t.Logf("Adding LB of type TCP")
	client := env.GetNitroClient()
	err := lbObj.Add(client)
	if err != nil {
		t.Errorf("LBApi add failed with %v", err)
	}
	t.Logf("Converting LB to type HTTP")
	lbObj.FrontendServiceType = "HTTP"
	lbObj.BackendServiceType = "HTTP"
	err = lbObj.Add(client)
	if err != nil {
		t.Errorf("Error converting LB from type tcp to http : %v", err)
	}
	lbObj.Delete(client)
}

func Test_ServiceGroupAPI_ip(t *testing.T) {
	client := env.GetNitroClient()
	client.AddResource("servicegroup", "svcgp1", map[string]interface{}{"servicegroupname": "svcgp1", "servicetype": "HTTP"})
	svcGpObj := NewServiceGroupAPI("svcgp1")
	svcGpObj.IsIPOnlySvcGroup = false

	svcGpObj.Members = []ServiceGroupMember{{IP: "1.1.1.1", Port: 80}, {IP: "2.2.2.2", Port: 9090}, {IP: "1.1.1.2", Port: 80}}
	err := svcGpObj.Add(client)
	if err != nil {
		t.Errorf("ServiceGroup members add failed with %v", err)
	}
	err = env.VerifyBindings(client, "servicegroup", "svcgp1", "servicegroupmember", []map[string]interface{}{{"ip": "1.1.1.1", "port": 80}, {"ip": "2.2.2.2", "port": 9090}, {"ip": "1.1.1.2", "port": 80}})
	if err != nil {
		t.Errorf("Config verification for add failed with error %v", err)
	}

	svcGpObj.Members = []ServiceGroupMember{{IP: "1.1.1.2", Port: 80}, {IP: "3.3.3.3", Port: 80}, {IP: "2.2.2.2", Port: 9090}}
	err = svcGpObj.Add(client)
	if err != nil {
		t.Errorf("ServiceGroup members update failed with %v", err)
	}
	err = env.VerifyBindings(client, "servicegroup", "svcgp1", "servicegroupmember", []map[string]interface{}{{"ip": "3.3.3.3", "port": 80}, {"ip": "2.2.2.2", "port": 9090}, {"ip": "1.1.1.2", "port": 80}})
	if err != nil {
		t.Errorf("Config verification for update failed with error %v", err)
	}
	client.DeleteResource("servicegroup", "svcgp1")
}

func Test_ServiceGroupAPI_domain(t *testing.T) {
	client := env.GetNitroClient()
	client.AddResource("servicegroup", "svcgp2", map[string]interface{}{"servicegroupname": "svcgp2", "servicetype": "HTTP"})
	svcGpObj := NewServiceGroupAPI("svcgp2")
	svcGpObj.IsIPOnlySvcGroup = false
	svcGpObj.IsLogProxySvcGrp = true
	svcGpObj.PromEP = "www_abc_org" // Prometheus Server Name.
	svcGpObj.Members = []ServiceGroupMember{{Domain: "www.google.com", Port: 80}, {Domain: "www.abc.org", Port: 9090}, {Domain: "www.facebook.com", Port: 80}}
	err := svcGpObj.Add(client)
	if err != nil {
		t.Errorf("ServiceGroup members add failed with %v", err)
		return
	}
	err = env.VerifyBindings(client, "servicegroup", "svcgp2", "servicegroupmember", []map[string]interface{}{{"servername": "www_google_com", "port": 80}, {"servername": "www_abc_org", "port": 9090}, {"servername": "www_facebook_com", "port": 80}})
	if err != nil {
		t.Errorf("Config verification for add failed with error %v", err)
		return
	}

	svcGpObj.Members = []ServiceGroupMember{{Domain: "www.googl1.com", Port: 8080}, {Domain: "www.abc.org", Port: 9090}, {Domain: "citrix.com", Port: 80}}
	err = svcGpObj.Add(client)
	if err != nil {
		t.Errorf("ServiceGroup members update failed with %v", err)
		return
	}
	err = env.VerifyBindings(client, "servicegroup", "svcgp2", "servicegroupmember", []map[string]interface{}{{"servername": "www_googl1_com", "port": 8080}, {"servername": "www_abc_org", "port": 9090}, {"servername": "citrix_com", "port": 80}})
	if err != nil {
		t.Errorf("Config verification for update failed with error %v", err)
	}
	client.DeleteResource("servicegroup", "svcgp2")
}

func Test_ServiceGroupAPI_desiredState(t *testing.T) {
	client := env.GetNitroClient()
	curBuild.release = 13.0
	curBuild.buildNo = 48.0
	// Case 1: Adding servicegroup with only IP members from the beginning
	client.AddResource("servicegroup", "svcgp1", map[string]interface{}{"servicegroupname": "svcgp1", "servicetype": "HTTP", "autoscale": "API"})
	svcGpObj := NewServiceGroupAPI("svcgp1")
	svcGpObj.Members = []ServiceGroupMember{{IP: "1.1.1.1", Port: 80}, {IP: "2.2.2.2", Port: 9090}, {IP: "1.1.1.2", Port: 80}}
	svcGpObj.IsLogProxySvcGrp = true
	svcGpObj.PromEP = "1.1.1.2"
	err := svcGpObj.Add(client)
	if err != nil {
		t.Errorf("Desired State API based ServiceGroup members add failed with %v", err)
	}
	err = env.VerifyBindings(client, "servicegroup", "svcgp1", "servicegroupmember", []map[string]interface{}{{"ip": "1.1.1.1", "port": 80}, {"ip": "2.2.2.2", "port": 9090}, {"ip": "1.1.1.2", "port": 80}})
	if err != nil {
		t.Errorf("Config verification for addition of IP only servicegroup members failed with error %v", err)
	}
	// Case 2: Add Servicegroup with mix of IP and domain based members
	client.AddResource("servicegroup", "svcgp2", map[string]interface{}{"servicegroupname": "svcgp2", "servicetype": "HTTP"})
	svcGpObj = NewServiceGroupAPI("svcgp2")
	svcGpObj.IsIPOnlySvcGroup = false
	svcGpObj.Members = []ServiceGroupMember{{IP: "1.1.1.2", Port: 80}, {Domain: "www.sample.com", Port: 80}, {IP: "2.2.2.2", Port: 9090}}
	err = svcGpObj.Add(client)
	if err != nil {
		t.Errorf("ServiceGroup members (IP + domain) update failed with %v", err)
	}
	err = env.VerifyBindings(client, "servicegroup", "svcgp2", "servicegroupmember", []map[string]interface{}{{"ip": "1.1.1.2", "port": 80}, {"ip": "2.2.2.2", "port": 9090}, {"servername": "www_sample_com", "port": 80}})
	if err != nil {
		t.Errorf("Config verification for update failed with error %v", err)
	}
	// Case 2.b: Now bind members of IP type only
	svcGpObj.Members = []ServiceGroupMember{{IP: "1.1.1.2", Port: 80}, {IP: "3.3.3.3", Port: 80}, {IP: "2.2.2.2", Port: 9090}}
	svcGpObj.IsIPOnlySvcGroup = true
	err = svcGpObj.Add(client)
	if err != nil {
		t.Errorf("Desired state API based ServiceGroup members update failed with %v", err)
	}
	err = env.VerifyBindings(client, "servicegroup", "svcgp2", "servicegroupmember", []map[string]interface{}{{"ip": "1.1.1.2", "port": 80}, {"ip": "2.2.2.2", "port": 9090}, {"ip": "3.3.3.3", "port": 80}})
	if err != nil {
		t.Errorf("Config verification for update from classic API to desired state API failed with error %v", err)
	}

	client.DeleteResource("servicegroup", "svcgp1")
	client.DeleteResource("servicegroup", "svcgp2")
}
