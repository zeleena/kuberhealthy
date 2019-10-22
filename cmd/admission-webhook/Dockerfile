FROM golang:1.13 AS builder
RUN apt-get upgrade -y && apt-get install git -y
ADD . /go/src/app
WORKDIR /go/src/app/cmd/admission-webhook
RUN go build -o app -v

FROM golang:alpine
COPY --from=builder /go/src/app/cmd/admission-webhook /app/app
RUN apk update && apk add ca-certificates
ENTRYPOINT /app/app