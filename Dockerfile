# STEP 1 build executable binary
FROM golang:1.12 as builder
# https://unix.stackexchange.com/questions/96892/what-does-adduser-disabled-login-do
RUN adduser --uid 32024 --disabled-login --gecos "" citrixuser

COPY . $GOPATH/src/citrix-istio-adaptor

#build the binary
RUN GOARCH=amd64 CGO_ENABLED=0 GOOS=linux go install -ldflags "-extldflags -static -s -w" citrix-istio-adaptor/istio-adaptor

# STEP 2 build a small image
# start from scratch

FROM scratch
# Copy our static executable
COPY --from=builder /go/bin/istio-adaptor /go/bin/istio-adaptor
COPY --from=builder /etc/passwd /etc/passwd
COPY Version /etc/

USER citrixuser
ENTRYPOINT ["/go/bin/istio-adaptor"]
