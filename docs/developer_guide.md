# Developer Guide

## Build Istio-adaptor

To build the `istio-adaptor`, you need to have the following software installed on your machine:
* Docker
* Make
* Golang v1.12

To build images, run the following command:
```
make build
```
To create Istio-adaptor container:
```
make docker_build
```

## Testing Istio-adaptor

Citrix's `istio-adaptor` is developed so as to work generically for ingress as well as sidecar proxy. So, testing `istio-adaptor` in any mode of Citrix ADC CPX is enough. Citrix `istio-adaptor`'s test coverage primarily focusses on [Unit testing](https://en.wikipedia.org/wiki/Unit_testing) of `istio-adaptor` code and [Integration testing](https://en.wikipedia.org/wiki/Integration_testing) with Citrix ADC. 
As a prerequisite for testing `istio-adaptor`, developer should [run Citrix ADC CPX](https://docs.citrix.com/en-us/citrix-adc-cpx/12-1/deploy-using-docker-image-file.html) in the same machine. 
Below environment variables should be set before running test command.

| Parameter                      | Description                   |
|--------------------------------|-------------------------------|
| `NS_TEST_IP`	| Citrix ADC Management IP |
| `NS_TEST_NITRO_PORT` | Citrix ADC REST API Port |
| `NS_TEST_LOGIN` | Citrix ADC Username | 
| `NS_TEST_PASSWORD` | Citrix ADC Password |


Tests with code coverage are invoked with `make utest`. This will trigger both unit and integration tests.

```
make utest
```
You can clean up using following command:
```
make clean
```


