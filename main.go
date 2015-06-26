package main

import (
	"runtime"

	"gopkg.in/redis.v3"

	"github.com/Quorumsco/proxy/controllers"
	"github.com/codegangsta/cli"
	"github.com/iogo-framework/application"
	"github.com/iogo-framework/cmd"
	"github.com/iogo-framework/logs"
	"github.com/iogo-framework/router"
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
	var app *application.Application
	var err error

	if app, err = application.New(); err != nil {
		return err
	}

	client := redis.NewClient(&redis.Options{Addr: ctx.String("redis")})

	if _, err := client.Ping().Result(); err != nil {
		return err
	}
	logs.Debug("Connected to Redis at %s", ctx.String("redis"))
	app.Components["Redis"] = client

	app.Mux = router.New()

	if ctx.Bool("debug") {
		app.Use(router.Logger)
	}

	app.Use(app.Apply)
	app.Get("/sessions", controllers.Proxy)

	app.Serve(ctx.String("listen"))

	return nil
}
