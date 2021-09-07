TARGETS=nsconfigengine adsclient xds-adaptor delayserver certkeyhandler tests

VERSION=0.9.9

DOCKER_CMD=docker run $(DOCKER_CMD_OPTIONS) -v `pwd`:/citrix-xds-adaptor -w /citrix-xds-adaptor --rm xds-build:$(VERSION)


build_builder:
	docker build --no-cache -t xds-build:$(VERSION) -f Dockerfile_build .

build-dev-docker:
	docker build --no-cache --build-arg=START_CONTAINER=xds-build:$(VERSION) -t xds-adaptor:$(VERSION) -f Dockerfile .

build: build_builder build-dev-docker
	
format:
	$(DOCKER_CMD) gofmt -w -d $(TARGETS)

check_format:
	test -z $(shell $(DOCKER_CMD) gofmt -l $(TARGETS))

lint:
	$(DOCKER_CMD) golint --set_exit_status $(TARGETS)

check: check_format lint

# Run Unit Tests with code-coverage
utest: unit_test integration_test coverage_report

create_certs:
	sh tests/create_cert.sh

destroy_certs:
	- rm -r tests/certs

create_deviceinfo:
	- mkdir -p tests/deviceinfo

destroy_deviceinfo:
	- rm -r tests/deviceinfo

coverage_report:
	$(DOCKER_CMD) gocovmerge integrationtestcov.out unittestcov.out > combinedcoverage.out
	$(DOCKER_CMD) go tool cover -func=combinedcoverage.out
	$(DOCKER_CMD) go tool cover -html=combinedcoverage.out -o combinedcoverage.html
	$(DOCKER_CMD) sh -c "gocov convert combinedcoverage.out | gocov-xml > combinedcoverage.xml"

NS_TEST_IP=""
INGRESS_ADC_NAME="ingress_adc"
SIDECAR_CPX_NAME="sidecar_test_cpx"
CPX_IMAGE=quay.io/citrix/citrix-k8s-cpx-ingress:13.0-64.35

unit_test:
	make create_certs
	make create_deviceinfo
	$(eval load := $(shell docker run --name $(SIDECAR_CPX_NAME) -dt --cap-add=NET_ADMIN -e EULA=yes -e KUBERNETES_TASK_ID="" -e NS_CPX_LITE=1 -v `pwd`/tests/deviceinfo:/var/deviceinfo $(CPX_IMAGE)))
	$(eval DOCKER_CMD_OPTIONS := --net=container:$(SIDECAR_CPX_NAME) -e NS_TEST_IP=127.0.0.1 -e NS_TEST_NITRO_PORT=80 -e NS_TEST_LOGIN=nsroot -e NS_TEST_PASSWORD=nsroot -e GOPROXY=https://proxy.golang.org,direct -v `pwd`/tests/deviceinfo:/var/deviceinfo )
	$(DOCKER_CMD) go test -p 1 -race -timeout 1m -cover -coverprofile=unittestcov.out -v /citrix-xds-adaptor/nsconfigengine /citrix-xds-adaptor/adsclient /citrix-xds-adaptor/xds-adaptor /citrix-xds-adaptor/delayserver /citrix-xds-adaptor/certkeyhandler
	docker kill $(SIDECAR_CPX_NAME)
	docker rm $(SIDECAR_CPX_NAME)
	make destroy_certs
	make destroy_deviceinfo

integration_test:
	make create_certs
	make create_deviceinfo
	$(eval load := $(shell docker run --name $(INGRESS_ADC_NAME) -dt --cap-add=NET_ADMIN -e EULA=yes -e KUBERNETES_TASK_ID="" -e NS_CPX_LITE=1 -v `pwd`/tests/deviceinfo:/var/deviceinfo $(CPX_IMAGE)))
	$(eval NS_TEST_IP := $(shell docker inspect --format '{{ .NetworkSettings.IPAddress }}' $(INGRESS_ADC_NAME)))
	$(eval DOCKER_CMD_OPTIONS := -e NS_TEST_IP=$(NS_TEST_IP) -e NS_TEST_NITRO_PORT=9080 -e NS_TEST_LOGIN=nsroot -e NS_TEST_PASSWORD=nsroot -e GOPROXY=https://proxy.golang.org,direct -v `pwd`/tests/deviceinfo:/var/deviceinfo )
	$(DOCKER_CMD) go test -race -timeout 2m -cover -coverprofile=integrationtestcov.out -coverpkg=citrix-xds-adaptor/adsclient,citrix-xds-adaptor/nsconfigengine -v /citrix-xds-adaptor/tests
	docker kill $(INGRESS_ADC_NAME)
	docker rm $(INGRESS_ADC_NAME)
	make destroy_certs
	make destroy_deviceinfo

clean_cpx:
	-docker kill $(INGRESS_ADC_NAME)
	-docker rm $(INGRESS_ADC_NAME)
	-docker kill $(SIDECAR_CPX_NAME)
	-docker rm $(SIDECAR_CPX_NAME)

docker_clean:
	docker rmi -f $$(docker images -q -f dangling=true) || true
	docker rmi -f xds-adaptor:$(VERSION) || true
	docker rmi -f xds-build:$(VERSION) || true

clean: clean_cpx destroy_certs destroy_deviceinfo
	- rm integrationtestcov.out unittestcov.out combinedcoverage.out combinedcoverage.html combinedcoverage.xml

clean-all: clean docker_clean
