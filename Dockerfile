# STEP 1 build executable binary
FROM golang:1.12 as builder

COPY . $GOPATH/src/citrix-istio-adaptor

#build the binary
RUN GOARCH=amd64 CGO_ENABLED=0 GOOS=linux go install -ldflags "-extldflags -static -s -w" citrix-istio-adaptor/istio-adaptor

# STEP 2 build a small image
# start from scratch

FROM scratch
# Copy our static executable
COPY --from=builder /go/bin/istio-adaptor /go/bin/istio-adaptor
COPY Version /etc/

ENTRYPOINT ["/go/bin/istio-adaptor"]
