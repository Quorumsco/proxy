FROM golang
MAINTAINER Douézan-Grard Guillaume - Quorums

ADD . /go/src/github.com/Quorumsco/contacts

WORKDIR /go/src/github.com/Quorumsco/contacts

RUN \
  go get && \
  go build main.go

EXPOSE 8080

ENTRYPOINT ["./main"]
