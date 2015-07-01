package main

import (
	"fmt"
	"log"
	"net/http"
	"runtime"

	"gopkg.in/redis.v3"

	"github.com/codegangsta/cli"
	"github.com/elazarl/goproxy"
	"github.com/iogo-framework/cmd"
	"github.com/iogo-framework/logs"
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	cmd := cmd.New()
	cmd.Name = "proxy"
	cmd.Usage = "Proxy for OAuth2 secure authentification"
	cmd.Version = "0.0.1"
	cmd.Before = serve
	cmd.Flags = append(cmd.Flags, []cli.Flag{
		cli.StringFlag{Name: "listen, l", Value: "localhost:8080", Usage: "http listening host:port"},
		cli.StringFlag{Name: "redis, r", Value: "localhost:6379", Usage: "redis host:port"},
		cli.BoolFlag{Name: "debug, d", Usage: "print debug information"},
		cli.HelpFlag,
	}...)
	cmd.RunAndExitOnError()
}

func serve(ctx *cli.Context) error {
	client := redis.NewClient(&redis.Options{Addr: ctx.String("redis")})

	if _, err := client.Ping().Result(); err != nil {
		return err
	}
	logs.Debug("Connected to Redis at %s", ctx.String("redis"))

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true

	var hasSessionHeaders = goproxy.ReqConditionFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) bool {
		req.ParseForm()
		return req.Header.Get("SID") != "" || (req.FormValue("username") != "" && req.FormValue("password") != "")
	})

	proxy.OnRequest(hasSessionHeaders).DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			fmt.Println("Add proxy client/secret ids")
			return r, nil
		},
	)

	logs.Info("Listening on %s", ctx.String("listen"))
	log.Fatal(http.ListenAndServe(ctx.String("listen"), proxy))

	return nil
}
