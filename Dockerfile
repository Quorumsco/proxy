FROM golang
MAINTAINER Douézan-Grard Guillaume - Quorums

ADD . /go/src/github.com/quorumsco/proxy

WORKDIR /go/src/github.com/quorumsco/proxy

RUN \
  go get && \
  go build

EXPOSE 8080

ENTRYPOINT ["./proxy"]
