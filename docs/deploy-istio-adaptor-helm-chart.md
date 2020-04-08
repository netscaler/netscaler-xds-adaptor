# Citrix ADC CPX in Istio Helm chart

The [Citrix `istio-adaptor` repository](https://github.com/citrix/citrix-istio-adaptor) contains [Helm](https://helm.sh) charts for installing Citrix ADC CPX as Ingress Gateway and sidecar proxy in [Istio](https://istio.io) version 1.3.0.


> **Note:** Charts may require access to `kube-system` namespace and may need cluster wide permissions for full functionality. You must install and configure Helm client and Tiller.

## Helm installation

For more information, see [Helm Installation Guide](https://github.com/citrix/citrix-helm-charts/blob/master/Helm_Installation_Kubernetes.md).

## Stable charts

The stable directory contains charts that are created and tested by Citrix.

### Charts

[`citrix-adc-istio-ingress-gateway`](https://github.com/citrix/citrix-helm-charts/tree/master/citrix-adc-istio-ingress-gateway) -Use this chart to deploy Citrix ADC as Ingress Gateway in Istio environment.

[`citrix-cpx-istio-sidecar-injector`](https://github.com/citrix/citrix-helm-charts/tree/master/citrix-cpx-istio-sidecar-injector) -Use this chart to deploy resources responsible for injecting Citrix ADC CPX as sidecar in Istio Service Mesh.

## Documentation

Chart's README describes the functionality and values.yaml shows the default values.
