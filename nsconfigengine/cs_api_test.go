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
	"testing"
)

func Test_CSApi_http(t *testing.T) {
	csObj := NewCSApi("cs1", "HTTP", "2.2.1.1", 80)
	csObj.AllowACL = true
	csObj.DefaultLbVserverName = "blackhole_http"
	client := env.GetNitroClient()
	t.Logf("Test CSApi Add")
	err := csObj.Add(client)
	if err != nil {
		t.Errorf("CSApi add failed with %v", err)
	}
	configs := []env.VerifyNitroConfig{
		{"csvserver", "cs1", map[string]interface{}{"name": "cs1", "servicetype": "HTTP", "ipv46": "2.2.1.1", "port": 80}},
		{"nsacl", "cs1", map[string]interface{}{"aclaction": "ALLOW", "aclname": "cs1", "destipval": "2.2.1.1", "destportval": "80", "priority": 80, "protocol": "TCP"}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Add cs1, error %v", err)
	}
	err = env.VerifyBindings(client, "csvserver", "cs1", "lbvserver", []map[string]interface{}{{"name": "cs1", "lbvserver": "blackhole_http"}})
	if err != nil {
		t.Errorf("Config verification failed for Add lbvserver binding cs1, error  %v", err)
	}
	t.Logf("Test CSApi Update")
	csObj.IP = "1.3.1.1"
	csObj.Port = 8080
	err = csObj.Add(client)
	if err != nil {
		t.Errorf("CSApi add failed with %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"csvserver", "cs1", map[string]interface{}{"name": "cs1", "servicetype": "HTTP", "ipv46": "1.3.1.1", "port": 8080}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Add cs1, error %v", err)
	}
	t.Logf("Test CSApi Delete")
	err = csObj.Delete(client)
	if err != nil {
		t.Errorf("CSApi delete failed with %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"csvserver", "cs1", map[string]interface{}{"name": "cs1"}},
		{"nsacl", "cs1", nil},
	}
	err = env.VerifyConfigBlockAbsence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Delete cs1, error %v", err)
	}
}

func Test_CSApi_http_tls(t *testing.T) {
	csObj := NewCSApi("cs2", "SSL", "2.2.1.1", 8443)
	csObj.AllowACL = false
	csObj.FrontendTLS = []SSLSpec{{CertFilename: "../tests/certs/certssvc2/svc2.citrixrootdummy2.com.crt", PrivateKeyFilename: "../tests/certs/certssvc2/svc2.citrixrootdummy2.com.key", SNICert: true}}
	client := env.GetNitroClient()
	t.Logf("Test CSApi Add")
	UploadCert(client, "../tests/certs/certssvc2/svc2.citrixrootdummy2.com.crt", "certssvc2_svc2", "../tests/certs/certssvc2/svc2.citrixrootdummy2.com.key", "certssvc2_svc2_key")
	err := csObj.Add(client)
	if err != nil {
		t.Errorf("CSApi add failed with %v", err)
	}
	configs := []env.VerifyNitroConfig{
		{"csvserver", "cs2", map[string]interface{}{"name": "cs2", "servicetype": "SSL", "ipv46": "2.2.1.1", "port": 8443}},
		{"sslcertkey", "certssvc2_svc2", map[string]interface{}{"cert": "/nsconfig/ssl/certssvc2_svc2", "certkey": "certssvc2_svc2", "key": "/nsconfig/ssl/certssvc2_svc2_key"}},
		{"sslvserver", "cs2", map[string]interface{}{"clientauth": "DISABLED", "vservername": "cs2"}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Add cs2, error %v", err)
	}
	err = env.VerifyBindings(client, "sslvserver", "cs2", "sslcertkey", []map[string]interface{}{{"ca": false, "certkeyname": "certssvc2_svc2", "vservername": "cs2"}})
	if err != nil {
		t.Errorf("Config verification failed for Add binding cs2, error %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"nsacl", "cs2", nil},
	}
	err = env.VerifyConfigBlockAbsence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Add cs2, error %v", err)
	}
	t.Logf("Test CSApi Delete")
	err = csObj.Delete(client)
	if err != nil {
		t.Errorf("CSApi delete failed with %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"csvserver", "cs2", nil},
	}
	err = env.VerifyConfigBlockAbsence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Delete cs2, error %v", err)
	}
}

func Test_CSApi_SSLfwd(t *testing.T) {
	csObj := NewCSApi("cs3", "SSL", "*", 443)
	csObj.AllowACL = false
	csObj.SSLForwarding = []SSLForwardSpec{{LbVserverName: "google_vsvr", SNINames: []string{"www.google.com", "www.google.in"}}, {LbVserverName: "citrix_vsvr", SNINames: []string{"www.citrix.com"}}}
	client := env.GetNitroClient()
	t.Logf("Test CSApi Add")
	err := csObj.Add(client)
	if err != nil {
		t.Errorf("CSApi add failed with %v", err)
	}
	configs := []env.VerifyNitroConfig{
		{"csvserver", "cs3", map[string]interface{}{"name": "cs3", "servicetype": "SSL", "ipv46": "*", "port": 443}},
		{"sslaction", "cs3_ssl_google_vsvr", map[string]interface{}{"name": "cs3_ssl_google_vsvr", "forward": "google_vsvr"}},
		{"sslaction", "cs3_ssl_citrix_vsvr", map[string]interface{}{"name": "cs3_ssl_citrix_vsvr", "forward": "citrix_vsvr"}},
		{"sslpolicy", "cs3_ssl_1", map[string]interface{}{"name": "cs3_ssl_1", "action": "cs3_ssl_google_vsvr", "rule": "(CLIENT.SSL.CLIENT_HELLO.SNI.CONTAINS(\"www.google.com\") || CLIENT.SSL.CLIENT_HELLO.SNI.CONTAINS(\"www.google.in\"))"}},
		{"sslpolicy", "cs3_ssl_2", map[string]interface{}{"name": "cs3_ssl_2", "action": "cs3_ssl_citrix_vsvr", "rule": "(CLIENT.SSL.CLIENT_HELLO.SNI.CONTAINS(\"www.citrix.com\"))"}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Add cs3, error %v", err)
	}
	err = env.VerifyBindings(client, "sslvserver", "cs3", "sslpolicy", []map[string]interface{}{
		{"vservername": "cs3", "policyname": "cs3_ssl_1", "priority": 1, "type": "CLIENTHELLO_REQ"},
		{"vservername": "cs3", "policyname": "cs3_ssl_2", "priority": 2, "type": "CLIENTHELLO_REQ"},
	})
	if err != nil {
		t.Errorf("Config verification failed for Add binding cs3, error %v", err)
	}
	t.Logf("Test CSApi SSLfwd update")
	csObj.SSLForwarding = []SSLForwardSpec{{LbVserverName: "citrix_vsvr", SNINames: []string{"www.citrix.com", "www.netscaler.com"}}}
	err = csObj.Add(client)
	if err != nil {
		t.Errorf("CSApi add failed with %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"csvserver", "cs3", map[string]interface{}{"name": "cs3", "servicetype": "SSL", "ipv46": "*", "port": 443}},
		{"sslaction", "cs3_ssl_citrix_vsvr", map[string]interface{}{"name": "cs3_ssl_citrix_vsvr", "forward": "citrix_vsvr"}},
		{"sslpolicy", "cs3_ssl_1", map[string]interface{}{"name": "cs3_ssl_1", "action": "cs3_ssl_citrix_vsvr", "rule": "(CLIENT.SSL.CLIENT_HELLO.SNI.CONTAINS(\"www.citrix.com\") || CLIENT.SSL.CLIENT_HELLO.SNI.CONTAINS(\"www.netscaler.com\"))"}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Add cs3, error %v", err)
	}
	err = env.VerifyBindings(client, "sslvserver", "cs3", "sslpolicy", []map[string]interface{}{
		{"vservername": "cs3", "policyname": "cs3_ssl_1", "priority": 1, "type": "CLIENTHELLO_REQ"},
	})
	if err != nil {
		t.Errorf("Config verification failed for Add binding cs3, error %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"sslaction", "cs3_ssl_google_vsvr", nil},
		{"sslpolicy", "cs3_ssl_2", nil},
	}
	err = env.VerifyConfigBlockAbsence(client, configs)
	if err != nil {
		t.Errorf("Stale entry removal verification failed for cs3, error %v", err)
	}
	t.Logf("Test CSApi Delete")
	err = csObj.Delete(client)
	if err != nil {
		t.Errorf("CSApi delete failed with %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"csvserver", "cs3", nil},
	}
	err = env.VerifyConfigBlockAbsence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Delete cs3, error %v", err)
	}

}

func Test_getMatchRule(t *testing.T) {
	cases := []struct {
		input          RouteMatch
		expectedOutput string
	}{
		{RouteMatch{}, "true"},
		{RouteMatch{Domains: []string{"*"}}, "((HTTP.REQ.HOSTNAME.REGEX_MATCH(re/.*/)))"},
		{RouteMatch{Domains: []string{""}}, "((HTTP.REQ.HOSTNAME.CONTAINS(\"\")))"},
		{RouteMatch{Domains: []string{"app-c.chaos-testing.svc.cluster.local", "app-c.chaos-testing.svc.cluster.local:8088"}}, "((HTTP.REQ.HOSTNAME.CONTAINS(\"app-c.chaos-testing.svc.cluster.local\") || HTTP.REQ.HOSTNAME.CONTAINS(\"app-c.chaos-testing.svc.cluster.local:8088\")))"},
		{RouteMatch{Domains: []string{"*"}, Prefix: "/abc"}, "((HTTP.REQ.HOSTNAME.REGEX_MATCH(re/.*/)) && HTTP.REQ.URL.Startswith(\"/abc\"))"},
		{RouteMatch{Domains: []string{"*"}, Path: "/def/login"}, "((HTTP.REQ.HOSTNAME.REGEX_MATCH(re/.*/)) && HTTP.REQ.URL.EQ(\"/def/login\"))"},
		{RouteMatch{Domains: []string{"*"}, Regex: "b.*"}, "((HTTP.REQ.HOSTNAME.REGEX_MATCH(re/.*/)) && HTTP.REQ.URL.REGEX_MATCH(re/b.*/))"},
		{RouteMatch{Domains: []string{"abc.com"}, Prefix: "/", Headers: []MatchHeader{{Name: "x-svc-custid", Exact: "AADS"}, {Name: "hello", Prefix: "world"}, {Name: "x-transaction", Regex: "WDE5F.*"}}}, "((HTTP.REQ.HOSTNAME.CONTAINS(\"abc.com\")) && HTTP.REQ.URL.Startswith(\"/\") && HTTP.REQ.HEADER(\"x-svc-custid\").EQ(\"AADS\") && HTTP.REQ.HEADER(\"hello\").STARTSWITH(\"world\") && HTTP.REQ.HEADER(\"x-transaction\").REGEX_MATCH(re/WDE5F.*/))"},
	}
	for _, c := range cases {
		if output := c.input.getMatchRule(); output != c.expectedOutput {
			t.Errorf("incorrect output for `%v` : expected `%s` but got `%s`", c.input, c.expectedOutput, output)
		}
	}
}

func Test_CSBindingsAPI(t *testing.T) {
	client := env.GetNitroClient()
	t.Logf("Test CSBindingsAPI Add")
	csObj := NewCSApi("cs4", "HTTP", "*", 80)
	err := csObj.Add(client)
	if err != nil {
		t.Errorf("CSApi Add failed with err %v", err)
	}
	csBindings := NewCSBindingsAPI(csObj.Name)
	csBindings.Bindings = []CSBinding{
		{Rule: RouteMatch{Domains: []string{"www.abc.com", "www.abc.in"}, Path: "/login"}, CsPolicy: CsPolicy{Canary: []Canary{{LbVserverName: "v1", LbVserverType: "HTTP", Weight: 80}, {LbVserverName: "v2", LbVserverType: "HTTP", Weight: 20}}}},
		{Rule: RouteMatch{Domains: []string{"www.abc.com", "www.abc.in"}, Prefix: "/"}, CsPolicy: CsPolicy{Canary: []Canary{{LbVserverName: "v1", LbVserverType: "HTTP"}}}},
		{Rule: RouteMatch{Domains: []string{"www.abc.com", "www.abc.in"}, Prefix: "/details"}, RwPolicy: RewritePolicy{PrefixRewrite: "/about", HostRewrite: "www.adcdetails.org", AddHeaders: []RwHeader{{Key: "hello", Value: "world"}, {Key: "come", Value: "go"}}}},
		{Rule: RouteMatch{Domains: []string{"www.another.in"}, Prefix: "/"}, RwPolicy: RewritePolicy{AddHeaders: []RwHeader{{Key: "time", Value: "any"}}}},
		{Rule: RouteMatch{Domains: []string{"www.another.in"}, Prefix: "/"}, CsPolicy: CsPolicy{Canary: []Canary{{LbVserverName: "vanother", LbVserverType: "HTTP", Persistency: &PersistencyPolicy{CookieName: "abracadabra", Timeout: 15}}}}},
		{Rule: RouteMatch{Domains: []string{"www.another.in"}, Prefix: "/products"}, ResPolicy: ResponderPolicy{RedirectHost: "www.another.com", RedirectPath: "/productsall"}},
		{Rule: RouteMatch{Domains: []string{"www.another.in"}, Path: "/random"}, ResPolicy: ResponderPolicy{RedirectHost: "www.anotherrandom.com"}},
		{Rule: RouteMatch{Domains: []string{"www.another.in"}, Path: "/team"}, ResPolicy: ResponderPolicy{RedirectPath: "/people"}},
	}
	t.Logf("Test CSBindingsAPI Add")
	err = csBindings.Add(client)
	if err != nil {
		t.Errorf("CSBindingsAPI Add for cs4 failed with err %v", err)
	}
	configs := []env.VerifyNitroConfig{
		{"csaction", "cs4_10", map[string]interface{}{"name": "cs4_10", "targetlbvserver": "v1"}},
		{"csaction", "cs4_20", map[string]interface{}{"name": "cs4_20", "targetlbvserver": "v2"}},
		{"cspolicy", "cs4_10", map[string]interface{}{"action": "cs4_10", "policyname": "cs4_10", "rule": "(((HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.com\") || HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.in\")) && HTTP.REQ.URL.EQ(\"/login\")) && sys.random.mul(100).lt(80))"}},
		{"cspolicy", "cs4_20", map[string]interface{}{"action": "cs4_20", "policyname": "cs4_20", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.com\") || HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.in\")) && HTTP.REQ.URL.EQ(\"/login\"))"}},
		{"csaction", "cs4_30", map[string]interface{}{"name": "cs4_30", "targetlbvserver": "v1"}},
		{"cspolicy", "cs4_30", map[string]interface{}{"action": "cs4_30", "policyname": "cs4_30", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.com\") || HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.in\")) && HTTP.REQ.URL.Startswith(\"/\"))"}},
		{"rewriteaction", "cs4_rw_80", map[string]interface{}{"name": "cs4_rw_80", "search": "text(\"/details\")", "stringbuilderexpr": "\"/about\"", "target": "http.REQ.URL", "type": "replace_all"}},
		{"rewritepolicy", "cs4_rw_80", map[string]interface{}{"action": "cs4_rw_80", "name": "cs4_rw_80", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.com\") || HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.in\")) && HTTP.REQ.URL.Startswith(\"/details\")) && http.req.url.contains(\"/details\") && http.req.url.contains(\"/details/\").not"}},
		{"rewriteaction", "cs4_rw_90", map[string]interface{}{"name": "cs4_rw_90", "stringbuilderexpr": "\"www.adcdetails.org\"", "target": "HTTP.REQ.HOSTNAME", "type": "replace"}},
		{"rewritepolicy", "cs4_rw_90", map[string]interface{}{"action": "cs4_rw_90", "name": "cs4_rw_90", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.com\") || HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.in\")) && HTTP.REQ.URL.Startswith(\"/details\"))"}},
		{"rewriteaction", "cs4_rw_100", map[string]interface{}{"name": "cs4_rw_100", "stringbuilderexpr": "\"world\"", "target": "hello", "type": "insert_http_header"}},
		{"rewritepolicy", "cs4_rw_100", map[string]interface{}{"action": "cs4_rw_100", "name": "cs4_rw_100", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.com\") || HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.in\")) && HTTP.REQ.URL.Startswith(\"/details\"))"}},
		{"rewriteaction", "cs4_rw_110", map[string]interface{}{"name": "cs4_rw_110", "stringbuilderexpr": "\"go\"", "target": "come", "type": "insert_http_header"}},
		{"rewritepolicy", "cs4_rw_110", map[string]interface{}{"action": "cs4_rw_110", "name": "cs4_rw_110", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.com\") || HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.in\")) && HTTP.REQ.URL.Startswith(\"/details\"))"}},
		{"rewriteaction", "cs4_rw_120", map[string]interface{}{"name": "cs4_rw_120", "stringbuilderexpr": "\"any\"", "target": "time", "type": "insert_http_header"}},
		{"rewritepolicy", "cs4_rw_120", map[string]interface{}{"action": "cs4_rw_120", "name": "cs4_rw_120", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.another.in\")) && HTTP.REQ.URL.Startswith(\"/\"))"}},
		{"lbvserver", "vanother", map[string]interface{}{"name": "vanother", "persistencetype": "COOKIEINSERT", "cookiename": "abracadabra", "timeout": 15}},
		{"csaction", "cs4_40", map[string]interface{}{"name": "cs4_40", "targetlbvserver": "vanother"}},
		{"cspolicy", "cs4_40", map[string]interface{}{"action": "cs4_40", "policyname": "cs4_40", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.another.in\")) && HTTP.REQ.URL.Startswith(\"/\"))"}},
		{"responderaction", "cs4_ra_10", map[string]interface{}{"name": "cs4_ra_10", "target": "\"http://www.another.com/productsall\"", "type": "redirect"}},
		{"responderpolicy", "cs4_ra_10", map[string]interface{}{"action": "cs4_ra_10", "name": "cs4_ra_10", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.another.in\")) && HTTP.REQ.URL.Startswith(\"/products\"))"}},
		{"responderaction", "cs4_ra_20", map[string]interface{}{"name": "cs4_ra_20", "target": "\"http://www.anotherrandom.com\"+HTTP.REQ.URL", "type": "redirect"}},
		{"responderpolicy", "cs4_ra_20", map[string]interface{}{"action": "cs4_ra_20", "name": "cs4_ra_20", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.another.in\")) && HTTP.REQ.URL.EQ(\"/random\"))"}},
		{"responderaction", "cs4_ra_30", map[string]interface{}{"name": "cs4_ra_30", "target": "HTTP.REQ.HOSTNAME + \"/people\"", "type": "redirect"}},
		{"responderpolicy", "cs4_ra_30", map[string]interface{}{"action": "cs4_ra_30", "name": "cs4_ra_30", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.another.in\")) && HTTP.REQ.URL.EQ(\"/team\"))"}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Add cs4, error %v", err)
	}
	err = env.VerifyBindings(client, "csvserver", "cs4", "cspolicy", []map[string]interface{}{
		{"name": "cs4", "policyname": "cs4_10", "priority": "10"},
		{"name": "cs4", "policyname": "cs4_20", "priority": "20"},
		{"name": "cs4", "policyname": "cs4_30", "priority": "30"},
		{"name": "cs4", "policyname": "cs4_40", "priority": "40"},
	})
	if err != nil {
		t.Errorf("Config verification failed for Add cspolicy binding cs4, error %v", err)
	}
	err = env.VerifyBindings(client, "csvserver", "cs4", "rewritepolicy", []map[string]interface{}{
		{"name": "cs4", "policyname": "cs4_rw_80", "priority": "80"},
		{"name": "cs4", "policyname": "cs4_rw_90", "priority": "90"},
		{"name": "cs4", "policyname": "cs4_rw_100", "priority": "100"},
		{"name": "cs4", "policyname": "cs4_rw_110", "priority": "110"},
		{"name": "cs4", "policyname": "cs4_rw_120", "priority": "120"},
	})
	if err != nil {
		t.Errorf("Config verification failed for Add rewrite policy binding cs4, error %v", err)
	}
	err = env.VerifyBindings(client, "csvserver", "cs4", "responderpolicy", []map[string]interface{}{
		{"name": "cs4", "policyname": "cs4_ra_10", "priority": "10"},
		{"name": "cs4", "policyname": "cs4_ra_20", "priority": "20"},
		{"name": "cs4", "policyname": "cs4_ra_30", "priority": "30"},
	})
	if err != nil {
		t.Errorf("Config verification failed for Add responder policy binding cs4, error %v", err)
	}
	t.Logf("Test CSBindingsAPI Update")
	csBindings = NewCSBindingsAPI(csObj.Name)
	csBindings.Bindings = []CSBinding{
		{Rule: RouteMatch{Domains: []string{"www.abc.com", "www.abc.in"}, Path: "/login"}, CsPolicy: CsPolicy{Canary: []Canary{{LbVserverName: "v1", LbVserverType: "HTTP", Weight: 80}, {LbVserverName: "v2", LbVserverType: "HTTP", Weight: 20}}}},
		{Rule: RouteMatch{Domains: []string{"www.abc.com", "www.abc.in"}, Prefix: "/"}, Fault: Fault{AbortPercent: 20, AbortHTTPStatus: 502}, CsPolicy: CsPolicy{Canary: []Canary{{LbVserverName: "v3", LbVserverType: "HTTP", Persistency: &PersistencyPolicy{HeaderName: "transaction-header"}}}}},
		{Rule: RouteMatch{Domains: []string{"www.abc.com", "www.abc.in"}, Prefix: "/details"}, RwPolicy: RewritePolicy{PrefixRewrite: "/about", HostRewrite: "www.adcdetails.org", AddHeaders: []RwHeader{{Key: "hello", Value: "world"}}}},
		{Rule: RouteMatch{Domains: []string{"www.another.in"}, Prefix: "/"}, Fault: Fault{DelayPercent: 15, DelaySeconds: 3}, RwPolicy: RewritePolicy{AddHeaders: []RwHeader{{Key: "time", Value: "any"}}}},
		{Rule: RouteMatch{Domains: []string{"www.another.in"}, Prefix: "/"}, CsPolicy: CsPolicy{Canary: []Canary{{LbVserverName: "vanother", LbVserverType: "HTTP"}}}},
		{Rule: RouteMatch{Domains: []string{"www.another.in"}, Prefix: "/products"}, ResPolicy: ResponderPolicy{RedirectHost: "www.another.com", RedirectPath: "/productsall"}},
		{Rule: RouteMatch{Domains: []string{"www.another.in"}, Path: "/random"}, ResPolicy: ResponderPolicy{RedirectHost: "www.anotherrandom.com"}},
		{Rule: RouteMatch{Domains: []string{"www.another.in"}, Path: "/team"}, ResPolicy: ResponderPolicy{RedirectPath: "/people"}},
	}
	err = csBindings.Add(client)
	if err != nil {
		t.Errorf("CSBindingsAPI Update for cs4 failed with err %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"csaction", "cs4_10", map[string]interface{}{"name": "cs4_10", "targetlbvserver": "v1"}},
		{"csaction", "cs4_20", map[string]interface{}{"name": "cs4_20", "targetlbvserver": "v2"}},
		{"cspolicy", "cs4_10", map[string]interface{}{"action": "cs4_10", "policyname": "cs4_10", "rule": "(((HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.com\") || HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.in\")) && HTTP.REQ.URL.EQ(\"/login\")) && sys.random.mul(100).lt(80))"}},
		{"cspolicy", "cs4_20", map[string]interface{}{"action": "cs4_20", "policyname": "cs4_20", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.com\") || HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.in\")) && HTTP.REQ.URL.EQ(\"/login\"))"}},
		{"lbvserver", "v3", map[string]interface{}{"name": "v3", "persistencetype": "RULE", "rule": "HTTP.REQ.HEADER(\"transaction-header\")", "servicetype": "HTTP", "timeout": 2}},
		{"csaction", "cs4_30", map[string]interface{}{"name": "cs4_30", "targetlbvserver": "v3"}},
		{"cspolicy", "cs4_30", map[string]interface{}{"action": "cs4_30", "policyname": "cs4_30", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.com\") || HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.in\")) && HTTP.REQ.URL.Startswith(\"/\"))"}},
		{"rewriteaction", "cs4_rw_80", map[string]interface{}{"name": "cs4_rw_80", "search": "text(\"/details\")", "stringbuilderexpr": "\"/about\"", "target": "http.REQ.URL", "type": "replace_all"}},
		{"rewritepolicy", "cs4_rw_80", map[string]interface{}{"action": "cs4_rw_80", "name": "cs4_rw_80", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.com\") || HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.in\")) && HTTP.REQ.URL.Startswith(\"/details\")) && http.req.url.contains(\"/details\") && http.req.url.contains(\"/details/\").not"}},
		{"rewriteaction", "cs4_rw_90", map[string]interface{}{"name": "cs4_rw_90", "stringbuilderexpr": "\"www.adcdetails.org\"", "target": "HTTP.REQ.HOSTNAME", "type": "replace"}},
		{"rewritepolicy", "cs4_rw_90", map[string]interface{}{"action": "cs4_rw_90", "name": "cs4_rw_90", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.com\") || HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.in\")) && HTTP.REQ.URL.Startswith(\"/details\"))"}},
		{"rewriteaction", "cs4_rw_100", map[string]interface{}{"name": "cs4_rw_100", "stringbuilderexpr": "\"world\"", "target": "hello", "type": "insert_http_header"}},
		{"rewritepolicy", "cs4_rw_100", map[string]interface{}{"action": "cs4_rw_100", "name": "cs4_rw_100", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.com\") || HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.in\")) && HTTP.REQ.URL.Startswith(\"/details\"))"}},
		{"rewriteaction", "cs4_rw_110", map[string]interface{}{"name": "cs4_rw_110", "stringbuilderexpr": "\"any\"", "target": "time", "type": "insert_http_header"}},
		{"rewritepolicy", "cs4_rw_110", map[string]interface{}{"action": "cs4_rw_110", "name": "cs4_rw_110", "rule": "(((HTTP.REQ.HOSTNAME.CONTAINS(\"www.another.in\")) && HTTP.REQ.URL.Startswith(\"/\")) && sys.random.mul(100).lt(15) && sys.http_callout(cs4_call_delay_3).length.gt(0))"}},
		{"rewriteaction", "cs4_rw_120", map[string]interface{}{"name": "cs4_rw_120", "stringbuilderexpr": "\"any\"", "target": "time", "type": "insert_http_header"}},
		{"rewritepolicy", "cs4_rw_120", map[string]interface{}{"action": "cs4_rw_120", "name": "cs4_rw_120", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.another.in\")) && HTTP.REQ.URL.Startswith(\"/\"))"}},
		{"lbvserver", "vanother", map[string]interface{}{"name": "vanother", "persistencetype": "NONE"}},
		{"csaction", "cs4_40", map[string]interface{}{"name": "cs4_40", "targetlbvserver": "vanother"}},
		{"cspolicy", "cs4_40", map[string]interface{}{"action": "cs4_40", "policyname": "cs4_40", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.another.in\")) && HTTP.REQ.URL.Startswith(\"/\"))"}},
		{"responderaction", "cs4_ra_10", map[string]interface{}{"name": "cs4_ra_10", "target": "\"HTTP/1.1 502 Bad Gateway\r\n\r\n\"", "type": "respondwith"}},
		{"responderpolicy", "cs4_ra_10", map[string]interface{}{"action": "cs4_ra_10", "name": "cs4_ra_10", "rule": "((((HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.com\") || HTTP.REQ.HOSTNAME.CONTAINS(\"www.abc.in\")) && HTTP.REQ.URL.Startswith(\"/\"))) && sys.random.mul(100).lt(20))"}},
		{"responderaction", "cs4_ra_20", map[string]interface{}{"name": "cs4_ra_20", "target": "\"http://www.another.com/productsall\"", "type": "redirect"}},
		{"responderpolicy", "cs4_ra_20", map[string]interface{}{"action": "cs4_ra_20", "name": "cs4_ra_20", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.another.in\")) && HTTP.REQ.URL.Startswith(\"/products\"))"}},
		{"responderaction", "cs4_ra_30", map[string]interface{}{"name": "cs4_ra_30", "target": "\"http://www.anotherrandom.com\"+HTTP.REQ.URL", "type": "redirect"}},
		{"responderpolicy", "cs4_ra_30", map[string]interface{}{"action": "cs4_ra_30", "name": "cs4_ra_30", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.another.in\")) && HTTP.REQ.URL.EQ(\"/random\"))"}},
		{"responderaction", "cs4_ra_40", map[string]interface{}{"name": "cs4_ra_40", "target": "HTTP.REQ.HOSTNAME + \"/people\"", "type": "redirect"}},
		{"responderpolicy", "cs4_ra_40", map[string]interface{}{"action": "cs4_ra_40", "name": "cs4_ra_40", "rule": "((HTTP.REQ.HOSTNAME.CONTAINS(\"www.another.in\")) && HTTP.REQ.URL.EQ(\"/team\"))"}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Add cs4, error %v", err)
	}
	err = env.VerifyBindings(client, "csvserver", "cs4", "cspolicy", []map[string]interface{}{
		{"name": "cs4", "policyname": "cs4_10", "priority": "10"},
		{"name": "cs4", "policyname": "cs4_20", "priority": "20"},
		{"name": "cs4", "policyname": "cs4_30", "priority": "30"},
		{"name": "cs4", "policyname": "cs4_40", "priority": "40"},
	})
	if err != nil {
		t.Errorf("Config verification failed for Add cspolicy binding cs4, error %v", err)
	}
	err = env.VerifyBindings(client, "csvserver", "cs4", "rewritepolicy", []map[string]interface{}{
		{"name": "cs4", "policyname": "cs4_rw_80", "priority": "80"},
		{"name": "cs4", "policyname": "cs4_rw_90", "priority": "90"},
		{"name": "cs4", "policyname": "cs4_rw_100", "priority": "100"},
		{"name": "cs4", "policyname": "cs4_rw_110", "priority": "110"},
		{"name": "cs4", "policyname": "cs4_rw_120", "priority": "120"},
	})
	if err != nil {
		t.Errorf("Config verification failed for Add rewrite policy binding cs4, error %v", err)
	}
	err = env.VerifyBindings(client, "csvserver", "cs4", "responderpolicy", []map[string]interface{}{
		{"name": "cs4", "policyname": "cs4_ra_10", "priority": "10"},
		{"name": "cs4", "policyname": "cs4_ra_20", "priority": "20"},
		{"name": "cs4", "policyname": "cs4_ra_30", "priority": "30"},
		{"name": "cs4", "policyname": "cs4_ra_40", "priority": "40"},
	})
	if err != nil {
		t.Errorf("Config verification failed for Add responder policy binding cs4, error %v", err)
	}

	t.Logf("CSApi delete")
	err = csObj.Delete(client)
	if err != nil {
		t.Errorf("CSApi delete for cs4 failed with error %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"csaction", "cs4_10", nil},
		{"csaction", "cs4_20", nil},
		{"csaction", "cs4_30", nil},
		{"csaction", "cs4_40", nil},
		{"cspolicy", "cs4_10", nil},
		{"cspolicy", "cs4_20", nil},
		{"cspolicy", "cs4_30", nil},
		{"cspolicy", "cs4_40", nil},
		{"responderaction", "cs4_ra_10", nil},
		{"responderaction", "cs4_ra_20", nil},
		{"responderaction", "cs4_ra_30", nil},
		{"responderaction", "cs4_ra_40", nil},
		{"responderpolicy", "cs4_ra_10", nil},
		{"responderpolicy", "cs4_ra_20", nil},
		{"responderpolicy", "cs4_ra_30", nil},
		{"responderpolicy", "cs4_ra_40", nil},
		{"rewriteaction", "cs4_rw_80", nil},
		{"rewriteaction", "cs4_rw_90", nil},
		{"rewriteaction", "cs4_rw_100", nil},
		{"rewriteaction", "cs4_rw_110", nil},
		{"rewriteaction", "cs4_rw_120", nil},
		{"rewritepolicy", "cs4_rw_80", nil},
		{"rewritepolicy", "cs4_rw_90", nil},
		{"rewritepolicy", "cs4_rw_100", nil},
		{"rewritepolicy", "cs4_rw_110", nil},
		{"rewritepolicy", "cs4_rw_120", nil},
	}
	err = env.VerifyConfigBlockAbsence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for Delete stale bindings for cs4, error %v", err)
	}

}
