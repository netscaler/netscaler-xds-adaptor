# Helm charts for Citrix ADC integration with Istio

The [citrix-helm-charts repository](https://github.com/citrix/citrix-helm-charts) contains [Helm](https://helm.sh) charts for installing Citrix ADC CPX as Ingress Gateway, Egress Gateway, and sidecar proxy in [Istio](https://istio.io) version 1.6.4.

> **Note:** Charts may require access to the `kube-system` namespace and require cluster wide permissions for full functionality. Install and configure the Helm client and Tiller.

## Helm installation

For more information, see [Helm Installation Guide](https://github.com/citrix/citrix-helm-charts/blob/master/Helm_Installation_Kubernetes.md).

## Stable charts

The stable directory contains charts which are created and tested by Citrix.

### Charts

[`citrix-adc-istio-ingress-gateway`](https://github.com/citrix/citrix-helm-charts/tree/master/citrix-adc-istio-ingress-gateway) -Use this chart to deploy Citrix ADC as an Ingress Gateway in an Istio environment.

[`citrix-cpx-istio-sidecar-injector`](https://github.com/citrix/citrix-helm-charts/tree/master/citrix-cpx-istio-sidecar-injector) -Use this chart to deploy resources responsible for injecting Citrix ADC CPX as a sidecar in Istio Service Mesh.

[`citrix-adc-istio-egress-gateway`](https://github.com/citrix/citrix-helm-charts/tree/master/citrix-adc-istio-egress-gateway) -Use this chart to deploy Citrix ADC as an Egress Gateway in an Istio environment.

## Documentation

Chart's README describes the functionality and `values.yaml` shows the default values.
