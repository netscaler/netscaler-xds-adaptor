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

func Test_getAuthnRule(t *testing.T) {
	cases := []struct {
		input          []AuthRuleMatch
		expectedOutput string
	}{
		{[]AuthRuleMatch{{Exact: "/abc"}, {Suffix: ".asp"}}, "(HTTP.REQ.URL.EQ(\"/abc\") || HTTP.REQ.URL.ENDSWITH(\".asp\"))"},
		{[]AuthRuleMatch{{Prefix: "/about"}, {Regex: "info.*"}}, "(HTTP.REQ.URL.STARTSWITH(\"/about\") || HTTP.REQ.URL.REGEX_MATCH(re/info.*/))"},
		{[]AuthRuleMatch{}, ""},
		{[]AuthRuleMatch{{}, {}, {}}, ""},
	}
	for _, c := range cases {
		if output := getAuthnRule(c.input); output != c.expectedOutput {
			t.Errorf("incorrect output for `%v` : expected `%s` but got `%s`", c.input, c.expectedOutput, output)
		}
	}
}

func Test_getAuthAudience(t *testing.T) {
	cases := []struct {
		inputAudiences []string
		inputReleaseNo float64
		inputBuildNo   float64
		expectedOutput string
	}{
		{[]string{"str1", "str2", "str3", "", "str4", "str5"}, 12.1, 53.4, "str1,str2,str3,,str4,str5"},
		{[]string{"str1", "str2", "str3", "", "str4", "str5"}, 12.1, 50, "str1"},
		{[]string{"1234567890-a-1234567890-b-1234567890-c-1234567890-d-1234567890-e-1234567890-f-1234567890-g-1234567890-h-1234567890-i-1234567890", "some other string"}, 13.0, 35.9, "1234567890-a-1234567890-b-1234567890-c-1234567890-d-1234567890-e-1234567890-f-1234567890-g-1234567890-h-1234567890-i-1234567890"},
		{[]string{"1234567890-a-1234567890-b-1234567890-c-1234567890-d-1234567890-e-1234567890-f-1234567890-g-1234567890-h-1234567890-i-123456789", "some other string"}, 13.0, 40.1, "1234567890-a-1234567890-b-1234567890-c-1234567890-d-1234567890-e-1234567890-f-1234567890-g-1234567890-h-1234567890-i-123456789"},
		{[]string{"1234567890-a-1234567890-b-1234567890-c-", "1234567890-d-1234567890-e-1234567890-f-", "1234567890-g-1234567890-h-1234567890-i-1234567890"}, 13.0, 30.1, "1234567890-a-1234567890-b-1234567890-c-"},
		{[]string{"1234567890-a-1234567890-b-1234567890-c-", "1234567890-d-1234567890-e-1234567890-f-", "1234567890-g-1234567890-h-1234567890-i-1234567890"}, 13.0, 42.1, "1234567890-a-1234567890-b-1234567890-c-,1234567890-d-1234567890-e-1234567890-f-"},
		{[]string{"1234567890-a-1234567890-b-1234567890-c-", "1234567890-d-1234567890-e-1234567890-f-", "1234567890-g-1234567890-h-1234567890-1234567890"}, 13.0, 42.1, "1234567890-a-1234567890-b-1234567890-c-,1234567890-d-1234567890-e-1234567890-f-,1234567890-g-1234567890-h-1234567890-1234567890"},
		{[]string{"1234567890-a-1234567890-b-1234567890-c-1234567890-d-1234567890-e-1234567890-f-1234567890-g-1234567890-h-1234567890-i-1234567890-j-", "aaa"}, 13.0, 40.2, "aaa"},
	}
	for _, c := range cases {
		if output := getAuthAudience(c.inputAudiences, c.inputReleaseNo, c.inputBuildNo); output != c.expectedOutput {
			t.Errorf("incorrect output for `%v` : expected `%s` but got `%s`", c, c.expectedOutput, output)
		}
	}
}

func Test_patset(t *testing.T) {
	client := env.GetNitroClient()
	t.Logf("Test Patset")
	audiences := []string{"string1", "string2", "string3", "string4"}
	confErr := newNitroError()
	_ = addPatSet(client, confErr, "csvsvrauthn", audiences)
	configs := []env.VerifyNitroConfig{
		{"policypatset", "csvsvrauthn", map[string]interface{}{"name": "csvsvrauthn"}},
	}
	err := env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for adding patset, error %v", err)
	}
	err = env.VerifyBindings(client, "policypatset", "csvsvrauthn", "pattern", []map[string]interface{}{
		{"name": "csvsvrauthn", "String": "string1"},
		{"name": "csvsvrauthn", "String": "string2"},
		{"name": "csvsvrauthn", "String": "string3"},
		{"name": "csvsvrauthn", "String": "string4"},
	})
	if err != nil {
		t.Errorf("Config verification failed for policy Patset bindings, error  %v", err)
	}
	t.Logf("Test patset Delete")
	authSpec := &AuthSpec{Name: "csvsvrauthn"}
	confErr = newNitroError()
	authSpec.deletePatSet(client, confErr)
	if confErr.getError() != nil {
		t.Errorf("deletePatSet for patset csvsvrauthn failed with %v", confErr.getError())
	}
	configs = []env.VerifyNitroConfig{
		{"policypatset", "csvsvrauthn", nil},
	}
	err = env.VerifyConfigBlockAbsence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for patset csvsvrauthn, error %v", err)
	}
	audiences = []string{}
	confErr = newNitroError()
	patset := addPatSet(client, confErr, "csvsvrauthn", audiences)
	if patset != "" {
		t.Errorf("Expected Empty Name but got %s", patset)
	}

}

func Test_auth(t *testing.T) {
	client := env.GetNitroClient()
	t.Logf("Test authAdd")
	authSpec := &AuthSpec{Name: "csvsvrauthn", IncludePaths: []AuthRuleMatch{{Prefix: "/login"}}, ExcludePaths: []AuthRuleMatch{{Suffix: ".net"}}, Issuer: "google", JwksURI: "https://www.google.auth.com/gettoken", Audiences: []string{"string1"}, JwtHeaders: []string{"header1", "header2"}, JwtParams: []string{"param1", "param2", "param3"}}
	confErr := newNitroError()
	authSpec.authAdd(client, confErr)
	if confErr.getError() != nil {
		t.Errorf("authAdd for csvsvrauthn failed with %v", confErr.getError())
	}
	configs := []env.VerifyNitroConfig{
		{"authenticationvserver", "csvsvrauthn", map[string]interface{}{"ipv46": "0.0.0.0", "name": "csvsvrauthn", "servicetype": "SSL"}},
		{"authenticationoauthaction", "csvsvrauthn_10", map[string]interface{}{"audience": "string1", "authorizationendpoint": "https://dummy.com", "certendpoint": "https://www.google.auth.com/gettoken", "clientid": "testcitrix", "issuer": "google", "name": "csvsvrauthn_10", "tokenendpoint": "https://dummy.com"}},
		{"authenticationpolicy", "csvsvrauthn_10", map[string]interface{}{"action": "csvsvrauthn_10", "name": "csvsvrauthn_10", "rule": "(HTTP.REQ.URL.STARTSWITH(\"/login\"))"}},
		{"authenticationpolicy", "csvsvrauthn_20", map[string]interface{}{"action": "NO_AUTHN", "name": "csvsvrauthn_20", "rule": "(HTTP.REQ.URL.ENDSWITH(\".net\"))"}},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_10", map[string]interface{}{"authenticationschema": "noschema", "name": "csvsvrauthn_lgnschm_10", "userexpression": "HTTP.REQ.HEADER(\"header1\")"}},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_10", map[string]interface{}{"action": "csvsvrauthn_lgnschm_10", "name": "csvsvrauthn_lgnschm_10", "rule": "(HTTP.REQ.URL.STARTSWITH(\"/login\")) && HTTP.REQ.HEADER(\"header1\").EXISTS"}},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_20", map[string]interface{}{"authenticationschema": "noschema", "name": "csvsvrauthn_lgnschm_20", "userexpression": "HTTP.REQ.HEADER(\"header2\")"}},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_20", map[string]interface{}{"action": "csvsvrauthn_lgnschm_20", "name": "csvsvrauthn_lgnschm_20", "rule": "(HTTP.REQ.URL.STARTSWITH(\"/login\")) && HTTP.REQ.HEADER(\"header2\").EXISTS"}},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_30", map[string]interface{}{"authenticationschema": "noschema", "name": "csvsvrauthn_lgnschm_30", "userexpression": "HTTP.REQ.URL.QUERY.VALUE(\"param1\")"}},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_30", map[string]interface{}{"action": "csvsvrauthn_lgnschm_30", "name": "csvsvrauthn_lgnschm_30", "rule": "(HTTP.REQ.URL.STARTSWITH(\"/login\")) && HTTP.REQ.URL.QUERY.VALUE(\"param1\").LENGTH.GT(0)"}},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_40", map[string]interface{}{"authenticationschema": "noschema", "name": "csvsvrauthn_lgnschm_40", "userexpression": "HTTP.REQ.URL.QUERY.VALUE(\"param2\")"}},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_40", map[string]interface{}{"action": "csvsvrauthn_lgnschm_40", "name": "csvsvrauthn_lgnschm_40", "rule": "(HTTP.REQ.URL.STARTSWITH(\"/login\")) && HTTP.REQ.URL.QUERY.VALUE(\"param2\").LENGTH.GT(0)"}},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_50", map[string]interface{}{"authenticationschema": "noschema", "name": "csvsvrauthn_lgnschm_50", "userexpression": "HTTP.REQ.URL.QUERY.VALUE(\"param3\")"}},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_50", map[string]interface{}{"action": "csvsvrauthn_lgnschm_50", "name": "csvsvrauthn_lgnschm_50", "rule": "(HTTP.REQ.URL.STARTSWITH(\"/login\")) && HTTP.REQ.URL.QUERY.VALUE(\"param3\").LENGTH.GT(0)"}},
	}
	err := env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for authAdd csvsvrauthn, error %v", err)
	}
	err = env.VerifyBindings(client, "authenticationvserver", "csvsvrauthn", "authenticationpolicy", []map[string]interface{}{
		{"gotopriorityexpression": "NEXT", "name": "csvsvrauthn", "policy": "csvsvrauthn_10", "priority": 10},
		{"gotopriorityexpression": "NEXT", "name": "csvsvrauthn", "policy": "csvsvrauthn_20", "priority": 20},
	})
	if err != nil {
		t.Errorf("Config verification failed for authAdd authenticationpolicy binding csvsvrauthn, error  %v", err)
	}
	err = env.VerifyBindings(client, "authenticationvserver", "csvsvrauthn", "authenticationloginschemapolicy", []map[string]interface{}{
		{"name": "csvsvrauthn", "policy": "csvsvrauthn_lgnschm_10", "priority": 10},
		{"name": "csvsvrauthn", "policy": "csvsvrauthn_lgnschm_20", "priority": 20},
		{"name": "csvsvrauthn", "policy": "csvsvrauthn_lgnschm_30", "priority": 30},
		{"name": "csvsvrauthn", "policy": "csvsvrauthn_lgnschm_40", "priority": 40},
		{"name": "csvsvrauthn", "policy": "csvsvrauthn_lgnschm_50", "priority": 50},
	})
	if err != nil {
		t.Errorf("Config verification failed for authAdd authenticationloginschemapolicy binding csvsvrauthn, error  %v", err)
	}
	t.Logf("Test authAdd update")
	authSpec = &AuthSpec{Name: "csvsvrauthn", IncludePaths: []AuthRuleMatch{{Prefix: "/logout"}}, Issuer: "google", JwksURI: "https://www.google.auth.com/gettokennew", Audiences: []string{"string2"}, JwtHeaders: []string{"header11", "header2", "header3"}, JwtParams: []string{"param2"}}
	confErr = newNitroError()
	authSpec.authAdd(client, confErr)
	if confErr.getError() != nil {
		t.Errorf("authAdd update for csvsvrauthn failed with %v", confErr.getError())
	}
	configs = []env.VerifyNitroConfig{
		{"authenticationvserver", "csvsvrauthn", map[string]interface{}{"ipv46": "0.0.0.0", "name": "csvsvrauthn", "servicetype": "SSL"}},
		{"authenticationoauthaction", "csvsvrauthn_10", map[string]interface{}{"audience": "string2", "authorizationendpoint": "https://dummy.com", "certendpoint": "https://www.google.auth.com/gettokennew", "clientid": "testcitrix", "issuer": "google", "name": "csvsvrauthn_10", "tokenendpoint": "https://dummy.com"}},
		{"authenticationpolicy", "csvsvrauthn_10", map[string]interface{}{"action": "csvsvrauthn_10", "name": "csvsvrauthn_10", "rule": "(HTTP.REQ.URL.STARTSWITH(\"/logout\"))"}},
		{"authenticationpolicy", "csvsvrauthn_20", map[string]interface{}{"action": "NO_AUTHN", "name": "csvsvrauthn_20", "rule": "true"}},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_10", map[string]interface{}{"authenticationschema": "noschema", "name": "csvsvrauthn_lgnschm_10", "userexpression": "HTTP.REQ.HEADER(\"header11\")"}},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_10", map[string]interface{}{"action": "csvsvrauthn_lgnschm_10", "name": "csvsvrauthn_lgnschm_10", "rule": "(HTTP.REQ.URL.STARTSWITH(\"/logout\")) && HTTP.REQ.HEADER(\"header11\").EXISTS"}},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_20", map[string]interface{}{"authenticationschema": "noschema", "name": "csvsvrauthn_lgnschm_20", "userexpression": "HTTP.REQ.HEADER(\"header2\")"}},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_20", map[string]interface{}{"action": "csvsvrauthn_lgnschm_20", "name": "csvsvrauthn_lgnschm_20", "rule": "(HTTP.REQ.URL.STARTSWITH(\"/logout\")) && HTTP.REQ.HEADER(\"header2\").EXISTS"}},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_30", map[string]interface{}{"authenticationschema": "noschema", "name": "csvsvrauthn_lgnschm_30", "userexpression": "HTTP.REQ.HEADER(\"header3\")"}},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_30", map[string]interface{}{"action": "csvsvrauthn_lgnschm_30", "name": "csvsvrauthn_lgnschm_30", "rule": "(HTTP.REQ.URL.STARTSWITH(\"/logout\")) && HTTP.REQ.HEADER(\"header3\").EXISTS"}},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_40", map[string]interface{}{"authenticationschema": "noschema", "name": "csvsvrauthn_lgnschm_40", "userexpression": "HTTP.REQ.URL.QUERY.VALUE(\"param2\")"}},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_40", map[string]interface{}{"action": "csvsvrauthn_lgnschm_40", "name": "csvsvrauthn_lgnschm_40", "rule": "(HTTP.REQ.URL.STARTSWITH(\"/logout\")) && HTTP.REQ.URL.QUERY.VALUE(\"param2\").LENGTH.GT(0)"}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for update authAdd csvsvrauthn, error %v", err)
	}
	err = env.VerifyBindings(client, "authenticationvserver", "csvsvrauthn", "authenticationpolicy", []map[string]interface{}{
		{"gotopriorityexpression": "NEXT", "name": "csvsvrauthn", "policy": "csvsvrauthn_10", "priority": 10},
		{"gotopriorityexpression": "NEXT", "name": "csvsvrauthn", "policy": "csvsvrauthn_20", "priority": 20},
	})
	if err != nil {
		t.Errorf("Config verification failed for update authAdd authenticationpolicy binding csvsvrauthn, error  %v", err)
	}
	err = env.VerifyBindings(client, "authenticationvserver", "csvsvrauthn", "authenticationloginschemapolicy", []map[string]interface{}{
		{"name": "csvsvrauthn", "policy": "csvsvrauthn_lgnschm_10", "priority": 10},
		{"name": "csvsvrauthn", "policy": "csvsvrauthn_lgnschm_20", "priority": 20},
		{"name": "csvsvrauthn", "policy": "csvsvrauthn_lgnschm_30", "priority": 30},
		{"name": "csvsvrauthn", "policy": "csvsvrauthn_lgnschm_40", "priority": 40},
	})
	if err != nil {
		t.Errorf("Config verification failed for update authAdd authenticationloginschemapolicy binding csvsvrauthn, error  %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"authenticationloginschema", "csvsvrauthn_lgnschm_50", nil},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_50", nil},
	}
	err = env.VerifyConfigBlockAbsence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for auth deleteStale csvsvrauthn, error %v", err)
	}
	t.Logf("Test authAdd update")
	authSpec = &AuthSpec{Name: "csvsvrauthn", Issuer: "google", JwksURI: "https://www.google.auth.com/gettokennew", Audiences: []string{}, JwtHeaders: []string{"header11", "header2", "header3"}, JwtParams: []string{"param2"}}
	confErr = newNitroError()
	authSpec.authAdd(client, confErr)
	if confErr.getError() != nil {
		t.Errorf("authAdd update for csvsvrauthn failed with %v", confErr.getError())
	}
	configs = []env.VerifyNitroConfig{
		{"authenticationvserver", "csvsvrauthn", map[string]interface{}{"ipv46": "0.0.0.0", "name": "csvsvrauthn", "servicetype": "SSL"}},
		{"authenticationoauthaction", "csvsvrauthn_10", map[string]interface{}{"authorizationendpoint": "https://dummy.com", "certendpoint": "https://www.google.auth.com/gettokennew", "clientid": "testcitrix", "issuer": "google", "name": "csvsvrauthn_10", "tokenendpoint": "https://dummy.com"}},
		{"authenticationpolicy", "csvsvrauthn_10", map[string]interface{}{"action": "csvsvrauthn_10", "name": "csvsvrauthn_10", "rule": "true"}},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_10", map[string]interface{}{"authenticationschema": "noschema", "name": "csvsvrauthn_lgnschm_10", "userexpression": "HTTP.REQ.HEADER(\"header11\")"}},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_10", map[string]interface{}{"action": "csvsvrauthn_lgnschm_10", "name": "csvsvrauthn_lgnschm_10", "rule": "HTTP.REQ.HEADER(\"header11\").EXISTS"}},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_20", map[string]interface{}{"authenticationschema": "noschema", "name": "csvsvrauthn_lgnschm_20", "userexpression": "HTTP.REQ.HEADER(\"header2\")"}},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_20", map[string]interface{}{"action": "csvsvrauthn_lgnschm_20", "name": "csvsvrauthn_lgnschm_20", "rule": "HTTP.REQ.HEADER(\"header2\").EXISTS"}},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_30", map[string]interface{}{"authenticationschema": "noschema", "name": "csvsvrauthn_lgnschm_30", "userexpression": "HTTP.REQ.HEADER(\"header3\")"}},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_30", map[string]interface{}{"action": "csvsvrauthn_lgnschm_30", "name": "csvsvrauthn_lgnschm_30", "rule": "HTTP.REQ.HEADER(\"header3\").EXISTS"}},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_40", map[string]interface{}{"authenticationschema": "noschema", "name": "csvsvrauthn_lgnschm_40", "userexpression": "HTTP.REQ.URL.QUERY.VALUE(\"param2\")"}},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_40", map[string]interface{}{"action": "csvsvrauthn_lgnschm_40", "name": "csvsvrauthn_lgnschm_40", "rule": "HTTP.REQ.URL.QUERY.VALUE(\"param2\").LENGTH.GT(0)"}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for update authAdd csvsvrauthn, error %v", err)
	}
	err = env.VerifyBindings(client, "authenticationvserver", "csvsvrauthn", "authenticationpolicy", []map[string]interface{}{
		{"gotopriorityexpression": "NEXT", "name": "csvsvrauthn", "policy": "csvsvrauthn_10", "priority": 10},
	})
	if err != nil {
		t.Errorf("Config verification failed for update authAdd authenticationpolicy binding csvsvrauthn, error  %v", err)
	}
	err = env.VerifyBindings(client, "authenticationvserver", "csvsvrauthn", "authenticationloginschemapolicy", []map[string]interface{}{
		{"name": "csvsvrauthn", "policy": "csvsvrauthn_lgnschm_10", "priority": 10},
		{"name": "csvsvrauthn", "policy": "csvsvrauthn_lgnschm_20", "priority": 20},
		{"name": "csvsvrauthn", "policy": "csvsvrauthn_lgnschm_30", "priority": 30},
		{"name": "csvsvrauthn", "policy": "csvsvrauthn_lgnschm_40", "priority": 40},
	})
	if err != nil {
		t.Errorf("Config verification failed for update authAdd authenticationloginschemapolicy binding csvsvrauthn, error  %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"authenticationloginschema", "csvsvrauthn_lgnschm_50", nil},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_50", nil},
	}
	err = env.VerifyConfigBlockAbsence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for auth deleteStale csvsvrauthn, error %v", err)
	}
	t.Logf("Test authAdd update")
	authSpec = &AuthSpec{Name: "csvsvrauthn", ExcludePaths: []AuthRuleMatch{{Suffix: ".net"}}, Issuer: "google", JwksURI: "https://www.google.auth.com/gettokennew", Audiences: []string{"string2"}, JwtHeaders: []string{"header11", "header2", "header3"}, JwtParams: []string{"param2"}}
	confErr = newNitroError()
	authSpec.authAdd(client, confErr)
	if confErr.getError() != nil {
		t.Errorf("authAdd update for csvsvrauthn failed with %v", confErr.getError())
	}
	configs = []env.VerifyNitroConfig{
		{"authenticationvserver", "csvsvrauthn", map[string]interface{}{"ipv46": "0.0.0.0", "name": "csvsvrauthn", "servicetype": "SSL"}},
		{"authenticationoauthaction", "csvsvrauthn_10", map[string]interface{}{"audience": "string2", "authorizationendpoint": "https://dummy.com", "certendpoint": "https://www.google.auth.com/gettokennew", "clientid": "testcitrix", "issuer": "google", "name": "csvsvrauthn_10", "tokenendpoint": "https://dummy.com"}},
		{"authenticationpolicy", "csvsvrauthn_10", map[string]interface{}{"action": "csvsvrauthn_10", "name": "csvsvrauthn_10", "rule": "(!(HTTP.REQ.URL.ENDSWITH(\".net\")))"}},
		{"authenticationpolicy", "csvsvrauthn_20", map[string]interface{}{"action": "NO_AUTHN", "name": "csvsvrauthn_20", "rule": "(HTTP.REQ.URL.ENDSWITH(\".net\"))"}},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_10", map[string]interface{}{"authenticationschema": "noschema", "name": "csvsvrauthn_lgnschm_10", "userexpression": "HTTP.REQ.HEADER(\"header11\")"}},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_10", map[string]interface{}{"action": "csvsvrauthn_lgnschm_10", "name": "csvsvrauthn_lgnschm_10", "rule": "(!(HTTP.REQ.URL.ENDSWITH(\".net\"))) && HTTP.REQ.HEADER(\"header11\").EXISTS"}},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_20", map[string]interface{}{"authenticationschema": "noschema", "name": "csvsvrauthn_lgnschm_20", "userexpression": "HTTP.REQ.HEADER(\"header2\")"}},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_20", map[string]interface{}{"action": "csvsvrauthn_lgnschm_20", "name": "csvsvrauthn_lgnschm_20", "rule": "(!(HTTP.REQ.URL.ENDSWITH(\".net\"))) && HTTP.REQ.HEADER(\"header2\").EXISTS"}},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_30", map[string]interface{}{"authenticationschema": "noschema", "name": "csvsvrauthn_lgnschm_30", "userexpression": "HTTP.REQ.HEADER(\"header3\")"}},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_30", map[string]interface{}{"action": "csvsvrauthn_lgnschm_30", "name": "csvsvrauthn_lgnschm_30", "rule": "(!(HTTP.REQ.URL.ENDSWITH(\".net\"))) && HTTP.REQ.HEADER(\"header3\").EXISTS"}},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_40", map[string]interface{}{"authenticationschema": "noschema", "name": "csvsvrauthn_lgnschm_40", "userexpression": "HTTP.REQ.URL.QUERY.VALUE(\"param2\")"}},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_40", map[string]interface{}{"action": "csvsvrauthn_lgnschm_40", "name": "csvsvrauthn_lgnschm_40", "rule": "(!(HTTP.REQ.URL.ENDSWITH(\".net\"))) && HTTP.REQ.URL.QUERY.VALUE(\"param2\").LENGTH.GT(0)"}},
	}
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for update authAdd csvsvrauthn, error %v", err)
	}
	err = env.VerifyBindings(client, "authenticationvserver", "csvsvrauthn", "authenticationpolicy", []map[string]interface{}{
		{"gotopriorityexpression": "NEXT", "name": "csvsvrauthn", "policy": "csvsvrauthn_10", "priority": 10},
		{"gotopriorityexpression": "NEXT", "name": "csvsvrauthn", "policy": "csvsvrauthn_20", "priority": 20},
	})
	if err != nil {
		t.Errorf("Config verification failed for update authAdd authenticationpolicy binding csvsvrauthn, error  %v", err)
	}
	err = env.VerifyBindings(client, "authenticationvserver", "csvsvrauthn", "authenticationloginschemapolicy", []map[string]interface{}{
		{"name": "csvsvrauthn", "policy": "csvsvrauthn_lgnschm_10", "priority": 10},
		{"name": "csvsvrauthn", "policy": "csvsvrauthn_lgnschm_20", "priority": 20},
		{"name": "csvsvrauthn", "policy": "csvsvrauthn_lgnschm_30", "priority": 30},
		{"name": "csvsvrauthn", "policy": "csvsvrauthn_lgnschm_40", "priority": 40},
	})
	if err != nil {
		t.Errorf("Config verification failed for update authAdd authenticationloginschemapolicy binding csvsvrauthn, error  %v", err)
	}
	configs = []env.VerifyNitroConfig{
		{"authenticationloginschema", "csvsvrauthn_lgnschm_50", nil},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_50", nil},
	}
	err = env.VerifyConfigBlockAbsence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for auth deleteStale csvsvrauthn, error %v", err)
	}

	t.Logf("Test authDelete")
	authSpec = &AuthSpec{Name: "csvsvrauthn"}
	confErr = newNitroError()
	authSpec.authDelete(client, confErr)
	if confErr.getError() != nil {
		t.Errorf("authDelete for csvsvrauthn failed with %v", confErr.getError())
	}
	configs = []env.VerifyNitroConfig{
		{"authenticationvserver", "csvsvrauthn", nil},
		{"authenticationoauthaction", "cs1auth_10", nil},
		{"authenticationpolicy", "cs1auth_10", nil},
		{"authenticationoauthaction", "cs1auth_20", nil},
		{"authenticationpolicy", "cs1auth_20", nil},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_10", nil},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_10", nil},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_20", nil},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_20", nil},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_30", nil},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_30", nil},
		{"authenticationloginschema", "csvsvrauthn_lgnschm_40", nil},
		{"authenticationloginschemapolicy", "csvsvrauthn_lgnschm_40", nil},
	}
	err = env.VerifyConfigBlockAbsence(client, configs)
	if err != nil {
		t.Errorf("Config verification failed for authDelete csvsvrauthn, error %v", err)
	}
}
