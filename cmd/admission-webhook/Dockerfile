FROM golang:1.13 AS builder
RUN apt-get upgrade -y && apt-get install git -y
ADD . /go/src/app
WORKDIR /go/src/app
RUN go get -v
RUN mkdir /app
RUN go build -o /app/app

FROM golang:alpine
COPY --from=builder go/src/app/app /app/app
RUN apk update && apk add ca-certificates
EXPOSE 80 443
ENTRYPOINT /app/app