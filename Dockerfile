# STEP 1 build executable binary
ARG START_CONTAINER=golang:1.16
FROM ${START_CONTAINER} as builder

# https://unix.stackexchange.com/questions/96892/what-does-adduser-disabled-login-do
RUN adduser --uid 32024 --disabled-login --gecos "" citrixuser

COPY . /citrix-xds-adaptor

WORKDIR /citrix-xds-adaptor

#build the binary
RUN GOARCH=amd64 CGO_ENABLED=0 GOOS=linux go build -o /go/bin/xds-adaptor -ldflags "-extldflags -static -s -w " github.com/citrix/citrix-xds-adaptor/xds-adaptor

# STEP 2 build a small image
# start from scratch

FROM scratch
# Copy our static executable
COPY --from=builder /go/bin/xds-adaptor /go/bin/xds-adaptor
COPY --from=builder /etc/passwd /etc/passwd

USER citrixuser
ENTRYPOINT ["/go/bin/xds-adaptor"]
