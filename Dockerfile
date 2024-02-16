FROM golang:1.21-alpine as build
RUN apk --no-cache add git
WORKDIR /go/src/github.com/owasp-amass/engine
COPY . .
RUN go install -v ./...

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=build /go/bin/amass_engine /bin/engine
COPY --from=build /go/bin/ae_isready /bin/ae_isready
ENV HOME /
RUN addgroup user \
    && adduser user -D -G user \
    && mkdir /.config \
    && mkdir /.config/amass \
    && chown -R user:user /.config/amass
USER user
WORKDIR /.config/amass
STOPSIGNAL SIGINT
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD ae_isready --host 127.0.0.1
ENTRYPOINT ["/bin/engine"]
