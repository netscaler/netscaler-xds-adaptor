# Developer Guide

## Build the Citrix xDS-adaptor

To build the `xDS-adaptor` container, you need to have the following software installed on your machine:

- Docker
- Make
- Go 1.13 version

To build images, run the following command:

    make build

To create the xDS-adaptor container, run the following command:

    make docker_build

## Testing the Citrix xDS-adaptor

Citrix's `xDS-adaptor` is developed to work generically for Ingress as well as sidecar proxy. So, testing `xDS-adaptor` in any mode of Citrix ADC CPX is enough. Citrix `xDS-adaptor`'s test coverage primarily focuses on [Unit testing](https://en.wikipedia.org/wiki/Unit_testing) of `xDS-adaptor` code and [Integration testing](https://en.wikipedia.org/wiki/Integration_testing) with Citrix ADC.
As a prerequisite for testing `xDS-adaptor`, the developer should [run Citrix ADC CPX](https://docs.citrix.com/en-us/citrix-adc-cpx/12-1/deploy-using-docker-image-file.html) in the same machine.
The following environment variables should be set before running the test command.

| Parameter                      | Description                   |
|--------------------------------|-------------------------------|
| `NS_TEST_IP`	| Citrix ADC management IP |
| `NS_TEST_NITRO_PORT` | Citrix ADC REST API port |
| `NS_TEST_LOGIN` | Citrix ADC user name | 
| `NS_TEST_PASSWORD` | Citrix ADC password |

Tests with code coverage are invoked with `make utest`. This triggers both unit and integration tests.


        make utest

You can clean up using the following command:


        make clean



