#!/bin/bash
# update CPX as sidecar proxy, and istio-adaptor container to configure CPX using Nitro
#
usage() {
    cat <<EOM
    This script will generate a yaml file from the input yaml file template.
    Template yaml file has proxy and istio-adaptor containers' image mentioned as variables. 
    Provide the desired CPX and istio-adaptor image info as arguments to this script.
    Usage:
    $(basename $0) --inputfile <yaml_file_template> --outputfile <output_yaml_file> --cpx-image-name <cpx-image-name> --cpx-image-tag <cpx-image-tag> --istio-adaptor-image-name <istio-adaptor-image-name> --istio-adaptor-image-tag <istio-adaptor-image-tag> --netscaler-url <netscaler-url> --vserver-ip <IPv4-Address> --username <username> --password <password> --namespace <name> --license-server-ip <IPv4 Address> --license-server-port <port>
    where
      <yaml_file_template> is the yaml file's template.
      <cpx-image-name> CPX image name. default value = quay.io/citrix/citrix-k8s-cpx-ingress"
      <cpx-image-tag> CPX Image tag. default value = 13.0-41.28"
      <istio-adaptor-image-name> Istio Adaptor image name. default value = quay.io/citrix/citrix-istio-adaptor"
      <istio-adaptor-image-tag> Istio Adaptor image's tag. default value = 1.1.0"
      <netscaler-url> URL for connecting with Citrix ADC via Nitro. Default value = http://127.0.0.1"
      <vserver-ip> IP Address to be used for Virtual Server."
      <namespace> Namespace of CPX sidecar injector webhook"
      <username> Username for Citrix ADC."
      <password> Password for Citrix ADC."
      <license-service-ip> Licensing Server IP."
      <license-service-port> Licensing Server Port. Default value: 27000"
      <ingressgateway-label> Citrix Ingress Gateway's label. Default value: citrix-ingressgateway"
EOM
}

if [ $# -eq 0 ]
then
    usage
    echo "Please run the script by specifying the input yaml file. Kindly note that input yaml file will be updated with CPX and istio-adaptor image info."
    exit
fi

while [[ $# -gt 0 ]]; do
    case ${1} in
        --inputfile)
            FILENAME="$2"
            shift
            ;;
        --outputfile)
            GENERATED_YAML="$2"
            shift
            ;;
        --cpx-image-name)
            CPX_IMAGE_NAME="$2"
            shift
            ;;
        --cpx-image-tag)
            CPX_IMAGE_TAG="$2"
            shift
            ;;
        --istio-adaptor-image-name)
            ISTIO_ADAPTOR_IMAGE="$2"
            shift
            ;;
        --istio-adaptor-image-tag)
            ISTIO_ADAPTOR_IMAGE_TAG="$2"
            shift
            ;;
        --netscaler-url)
            NETSCALER_URL="$2"
            shift
            ;;
        --vserver-ip)
            VSERVER_IP="$2"
            shift
            ;;
        --namespace)
            NAMESPACE="$2"
            shift
            ;;
        --username)
            USERNAME="$2"
            shift
            ;;
        --password)
            PASSWORD="$2"
            shift
            ;;
        --license-server-ip)
            LS_IP="$2"
            shift
            ;;
        --license-server-port)
            LS_PORT="$2"
            shift
            ;;
        --ingressgateway-label)
            INGRESSGATEWAY_LABEL="$2"
            shift
            ;;
        *)
            usage
            ;;
    esac
    shift
done

if [ -z ${FILENAME} ]
then
    echo "Please mention the input file."
    exit
fi

if [ -z ${GENERATED_YAML} ]
then
    echo "Please mention the output file name"
    exit
fi

# default values
[ -z ${CPX_IMAGE_NAME} ] && CPX_IMAGE_NAME=quay.io/citrix/citrix-k8s-cpx-ingress
[ -z ${CPX_IMAGE_TAG} ] && CPX_IMAGE_TAG=13.0-41.28
[ -z ${ISTIO_ADAPTOR_IMAGE} ] && ISTIO_ADAPTOR_IMAGE=quay.io/citrix/citrix-istio-adaptor
[ -z ${ISTIO_ADAPTOR_IMAGE_TAG} ] && ISTIO_ADAPTOR_IMAGE_TAG=1.1.0
[ -z ${USERNAME} ] && USERNAME=nsroot
[ -z ${PASSWORD} ] && PASSWORD=nsroot
[ -z ${NETSCALER_URL} ] && NETSCALER_URL=http://127.0.0.1
[ -z ${VSERVER_IP} ] && VSERVER_IP=""
[ -z ${NAMESPACE} ] && NAMESPACE="citrix-system"
[ -z ${LS_IP} ] && LS_IP="\"\""
[ -z ${LS_PORT} ] && LS_PORT=27000
[ -z ${INGRESSGATEWAY_LABEL} ] && INGRESSGATEWAY_LABEL="citrix-ingressgateway"

USERNAME="$(echo -n $USERNAME | base64 )"
PASSWORD="$(echo -n $PASSWORD | base64 )"

# Extract NSIP from the NETSCALER_URL for exporter's target-nsip 
EXPORTER_NSIP=${NETSCALER_URL}
EXPORTER_NSIP=${EXPORTER_NSIP#*//} #removes characters upto // from the begining
EXPORTER_NSIP=${EXPORTER_NSIP%:*} #removes trailing characters after colon (:)
if [ $EXPORTER_NSIP == "localhost" ]; then
        EXPORTER_NSIP='127.0.0.1'
fi

echo "# File generated using generate-yaml.sh script" > $GENERATED_YAML
cat $FILENAME >> $GENERATED_YAML
sed -i'' -e "s|{CPX_IMAGE_NAME}|${CPX_IMAGE_NAME}|" $GENERATED_YAML
sed -i'' -e "s|{CPX_IMAGE_TAG}|${CPX_IMAGE_TAG}|" $GENERATED_YAML
sed -i'' -e "s|{ISTIO_ADAPTOR_IMAGE}|${ISTIO_ADAPTOR_IMAGE}|" $GENERATED_YAML
sed -i'' -e "s|{ISTIO_ADAPTOR_IMAGE_TAG}|${ISTIO_ADAPTOR_IMAGE_TAG}|" $GENERATED_YAML
sed -i'' -e "s|{ISTIO_ADAPTOR_IMAGE_TAG}|${ISTIO_ADAPTOR_IMAGE_TAG}|" $GENERATED_YAML
sed -i'' -e "s|{NETSCALER_URL}|${NETSCALER_URL}|" $GENERATED_YAML
sed -i'' -e "s|{VSERVER_IP}|${VSERVER_IP}|" $GENERATED_YAML
sed -i'' -e "s|{NAMESPACE}|${NAMESPACE}|" $GENERATED_YAML
sed -i'' -e "s|{USERNAME}|${USERNAME}|" $GENERATED_YAML
sed -i'' -e "s|{PASSWORD}|${PASSWORD}|" $GENERATED_YAML
sed -i'' -e "s|{EXPORTER_NSIP}|${EXPORTER_NSIP}|" $GENERATED_YAML
sed -i'' -e "s|{LS_IP}|${LS_IP}|" $GENERATED_YAML
sed -i'' -e "s|{LS_PORT}|${LS_PORT}|" $GENERATED_YAML
sed -i'' -e "s|{INGRESSGATEWAY_LABEL}|${INGRESSGATEWAY_LABEL}|" $GENERATED_YAML
echo "Generated Citrix ADC yaml $GENERATED_YAML. Apply this yaml file in the namespace where Citrix ADC services are running."
