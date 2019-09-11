.PHONY: docker_build test clean coverage 
TARGETS=nsconfigengine adsclient istio-adaptor tests

build:
	go install citrix-istio-adaptor/istio-adaptor
 
docker_build:
	docker build --no-cache -t istio-adaptor:latest -f Dockerfile .

format:
	gofmt -w -d $(TARGETS)

check_format:
	test -z $(shell gofmt -l $(TARGETS))

lint:
	go get golang.org/x/lint/golint
	golint --set_exit_status $(TARGETS)

check: check_format lint

# Run Unit Tests with code-coverage
utest: unit_test integration_test coverage_report

unit_test:
	go test -p 1 -race -timeout 1m -cover -coverprofile=unittestcov.out -v citrix-istio-adaptor/nsconfigengine citrix-istio-adaptor/adsclient citrix-istio-adaptor/istio-adaptor

integration_test:
	go test -race -timeout 1m -cover -coverprofile=integrationtestcov.out -coverpkg=citrix-istio-adaptor/adsclient,citrix-istio-adaptor/nsconfigengine -v citrix-istio-adaptor/tests

coverage_report:
	go get github.com/wadey/gocovmerge
	gocovmerge integrationtestcov.out unittestcov.out > combinedcoverage.out
	go tool cover -func=combinedcoverage.out
	go tool cover -html=combinedcoverage.out -o combinedcoverage.html

clean:
	- rm integrationtestcov.out unittestcov.out combinedcoverage.out combinedcoverage.html
