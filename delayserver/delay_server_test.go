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

package delayserver

import (
	"citrix-xds-adaptor/tests/env"
	"testing"
	"time"
)

func Test_startHTTPDelayServer(t *testing.T) {
	t.Logf("Test HTTPServer")
	StartDelayServer()
	startTime := time.Now()
	code, resp, err1 := env.DoHTTPGet("http://localhost:" + delayServerPort + "/?sleep=1")
	endTime := time.Now()
	if err1 != nil {
		t.Errorf("http get returned error: %v", err1)
	}
	t.Logf("HTTPget returned code:%d response:%s", code, resp)
	if code != 200 {
		t.Errorf("Expected 200 OK response, received %d", code)
	}
	if int(endTime.Sub(startTime)) < 1 {
		t.Errorf("Expected 1s sleep")
	}
}
