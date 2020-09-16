![Citrix Logo](docs/media/Citrix_icon.png)

# Citrix ADC integration with xDS-based service mesh

[![Docker Repository on Quay](https://quay.io/repository/citrix/citrix-istio-adaptor/status "Docker Repository on Quay")](https://quay.io/repository/citrix/citrix-istio-adaptor)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./license/LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/citrix/citrix-istio-adaptor.svg)](https://github.com/citrix/citrix-istio-adaptor/issues)
[![GitHub stars](https://img.shields.io/github/stars/citrix/citrix-istio-adaptor.svg)](https://github.com/citrix/citrix-istio-adaptor/stargazers)
[![HitCount](http://hits.dwyl.io/citrix/citrix-istio-adaptor.svg)](http://hits.dwyl.io/citrix/citrix-istio-adaptor)

---

## Description

This repository contains an integration of [Citrix ADC](https://www.citrix.com/products/citrix-adc/platforms.html) with the [xDS-API](https://github.com/envoyproxy/data-plane-api) based service mesh.

# Table of contents

1. [Introduction](#introduction)
5. [Features](#features)
7. [Blogs](#blogs)
8. [Release Notes](#release-notes)
9. [Contributions](#contributions)
10. [Questions](#questions)
11. [Issues](#issues)
12. [Code of Conduct](#code-of-conduct)
13. [Licensing](#licensing)

## <a name="introduction">Introduction</a>

A service mesh is an infrastructure layer that manages communication between microservices. It provides capabilities such as service discovery, load balancing, security, and monitoring. A service mesh helps to connect, monitor, and secure microservices. [Citrix ADC](https://www.citrix.com/products/citrix-adc/platforms.html) has advanced traffic management capabilities for enhancing application performance and it provides comprehensive security. Citrix ADC integration with service meshes allows you to secure and optimize the traffic for applications in a service mesh using Citrix ADC features.

The `xDS-adaptor` is a container provided by Citrix for integrating Citrix ADC with service mesh control plane implementations based on xDS APIs (Istio, Consul, and so on). It communicates with the service mesh control plane and listens for updates by acting as a gRPC client to the control plane API server. Based on the updates from the control plane, the xDS-Adaptor generates the equivalent Citrix ADC configuration.

## <a name="Citrix-ADC-integration-with-Istio">Citrix ADC integration with Istio</a>

Citrix ADC integration with Istio allows you to secure and optimize traffic for applications in the service mesh using the Citrix ADC features.

For more information on how to integrate Citrix ADC with Istio, see [Citrix ADC integration with Istio](./docs/istio-integration/README.md).

## <a name="features">Features</a>

The features which are supported on a Citrix ADC in a service mesh can be broadly categorized into the following:

- Traffic management
- Security
- Observability

### Traffic management

Citrix ADC supports the following traffic management features in a service mesh.

-  Service discovery
-  Load balancing
-  Secure ingress
-  Weighted clusters
-  HTTP rewrite
-  HTTP redirect

### Security

Some important security features, which are supported on the Citrix ADC, are the following:

-  Authentication policy
-  Monitoring of service mesh certificates and keys

#### Authentication policy

-  Transport authentication or service-to-service authentication using mutual TLS.

#### Monitoring of service mesh certificates and keys

The `xDS-adaptor` monitors the folder where a service mesh deploys certificates and keys for mutual TLS authentication between Citrix ADC proxies. After an update of certificate and key, the `xDS-adaptor` loads the new certificate and key to the Citrix ADC.

### Observability

When a service is deployed in a service mesh, users may be interested to get insights about the service behavior. Citrix ADC proxy provides a rich set of in-built metrics to provide insights about the service behavior. When Citrix ADC CPX is deployed as a sidecar, these metrics represent the telemetry data for an application. It helps to reduce the burden of application developers by eliminating the need to include a lot of instrumentation code in the application. Instead, the developer can focus on the core application logic.

Citrix has built a couple of auxiliary tools such as [Citrix ADC Metrics Exporter](https://github.com/citrix/citrix-adc-metrics-exporter) and [Citrix Observability Exporter](https://github.com/citrix/citrix-observability-exporter) which help to export metrics and transactional data to observability tools such as Prometheus, Zipkin, Kafka, and so on.


The statistical data of a Citrix ADC ingress device can be exported to the Prometheus using [Citrix ADC Metrics Exporter](https://github.com/citrix/citrix-adc-metrics-exporter).

[Citrix Observability Exporter](https://github.com/citrix/citrix-observability-exporter) (COE) is a microservice designed to collect metrics from Citrix ADCs, and export them to observability tools such as Zipkin, Kafka, and Prometheus.
For more information about COE, see this [link](https://github.com/citrix/citrix-observability-exporter).

## <a name="blogs">Blogs</a>

Following is a list of blogs which explains the integration of Citrix ADC with service mesh.

- [Citrix ADC as an Istio Ingress Gateway: Part 1 Deployment](https://www.citrix.com/blogs/2019/11/13/citrix-adc-as-an-istio-ingress-gateway-part-1-deployment/)
- [Citrix ADC as an Istio Ingress Gateway: Part 2 Configuration](https://www.citrix.com/blogs/2019/11/14/citrix-adc-as-an-istio-ingress-gateway-part-2-configuration/)
- [Citrix ADC in OpenShift Service Mesh](https://blog.openshift.com/citrix-adc-in-openshift-service-mesh/)
- [Traffic Mirroring: Risk-free app upgrades in Istio with Citrix ADC](https://www.citrix.com/blogs/2020/04/29/traffic-mirroring-risk-free-app-upgrades-in-istio-with-citrix-adc/)
- [End-user authentication in an Istio service mesh with Citrix](https://www.citrix.com/blogs/2020/03/19/end-user-authentication-in-istio-service-mesh-with-citrix/)
- [Outlier detection using Citrix ADC in Istio service mesh](https://www.citrix.com/blogs/2020/07/15/outlier-detection-using-citrix-adc-in-istio-service-mesh/)

## <a name="release-notes">Release notes</a>

Click [here](docs/release-notes.md) for the release notes of the latest Citrix `xDS-adaptor`.

## <a name="contributions">Contributions</a>

Contributions are always welcome! Read the [Developer Guide](docs/developer-guide.md).

## <a name="questions">Questions</a>

For questions and support, the following channels are available:

-  [Citrix Discussion Forum](https://discussions.citrix.com/)
-  [Citrix ADC CPX Slack Channel](https://citrixadccloudnative.slack.com/)
  
To request an invitation to participate in the Slack channel, provide your email address using this form: [https://podio.com/webforms/22979270/1633242](https://podio.com/webforms/22979270/1633242)

## <a name="issues">Issues</a>

Report issues in detail. You can use the following command to collect the logs:

    Get Logs: kubectl logs <podname> -c xds-adaptor -n <namespace> > log_file

## <a name="code-of-conduct">Code of Conduct</a>

This project adheres to the [Kubernetes Community Code of Conduct](https://github.com/kubernetes/community/blob/master/code-of-conduct.md). By participating in this project, you agree to abide by its terms.

## <a name="licensing">Licensing</a>

The Citrix `xDS-adaptor` is licensed with [Apache License 2.0](license/LICENSE)
