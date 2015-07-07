FROM golang
MAINTAINER Douézan-Grard Guillaume - Quorums

RUN go get github.com/quorumsco/proxy

ADD . /go/src/github.com/quorumsco/proxy

WORKDIR /go/src/github.com/quorumsco/proxy

RUN \
  go get -u && \
  go build

EXPOSE 8080

ENTRYPOINT ["./proxy"]
