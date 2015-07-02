package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"runtime"
	"strings"

	"gopkg.in/redis.v3"

	"github.com/codegangsta/cli"
	"github.com/elazarl/goproxy"
	"github.com/iogo-framework/cmd"
	"github.com/iogo-framework/logs"
	"github.com/pborman/uuid"
	"github.com/quorumsco/proxy/components"
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
		cli.StringFlag{Name: "listen, l", Value: "0.0.0.0:8080", Usage: "http listening host:port"},
		cli.StringFlag{Name: "redis, r", Value: "localhost:6379", Usage: "redis host:port"},
		cli.BoolFlag{Name: "debug, d", Usage: "print debug information"},
		cli.HelpFlag,
	}...)
	cmd.RunAndExitOnError()
}

func serve(ctx *cli.Context) error {
	if len(ctx.Args()) < 2 {
		fmt.Println("Missing required arguments")
		cli.ShowAppHelp(ctx)
		return nil
	}

	clientID := ctx.Args()[0]
	clientSecret := ctx.Args()[1]

	client := redis.NewClient(&redis.Options{Addr: ctx.String("redis")})
	if _, err := client.Ping().Result(); err != nil {
		return err
	}
	logs.Debug("Connected to Redis at %s", ctx.String("redis"))
	store := components.NewRedisStore(client)

	proxy := goproxy.NewProxyHttpServer()
	if ctx.Bool("debug") {
		proxy.Verbose = true
	}

	// Treat only requests with an SID cookie or POSTing username and password.
	var session = goproxy.ReqConditionFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) bool {
		_, err := req.Cookie("SID")
		return err == nil || (req.Method == "POST" && req.FormValue("username") != "" && req.FormValue("password") != "") // The form is already parsed.
	})

	proxy.OnRequest(session).DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			cookie, err := req.Cookie("SID")
			if err == nil {
				session, err := store.Load(cookie.Value)
				if err != nil {
					return nil, nil
				}
				req.Header.Add("Authorization", "Bearer "+session.AccessToken)
				return req, nil
			}

			// Perform an OAuth "Resource Owner Password Credentials Grant"
			req.Form.Add("grant_type", "password")
			req.SetBasicAuth(clientID, clientSecret)

			// We must update the body and the content size for our new post value.
			var buffer io.Reader = strings.NewReader(req.Form.Encode())
			req.Body = ioutil.NopCloser(buffer)
			switch v := buffer.(type) {
			case *bytes.Buffer:
				req.ContentLength = int64(v.Len())
			case *bytes.Reader:
				req.ContentLength = int64(v.Len())
			case *strings.Reader:
				req.ContentLength = int64(v.Len())
			}

			req.RequestURI = "" // Must be removed for client requests
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				return nil, nil
			}
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, nil
			}

			// TODO: Check http status for errors
			access := new(components.AccessData)
			if err := json.Unmarshal(body, access); err != nil {
				return nil, nil
			}
			session := &components.Session{
				ID:           strings.TrimRight(base64.StdEncoding.EncodeToString(uuid.NewRandom()), "="),
				AccessToken:  access.AccessToken,
				RefreshToken: access.RefreshToken,
				ExpiresIn:    access.ExpiresIn,
			}
			if err := store.Save(session); err != nil {
				return nil, nil
			}

			// Give a json response to clients
			resp = goproxy.NewResponse(req, "text/plain", http.StatusOK, "")
			cookie = &http.Cookie{Name: "SID", Value: session.ID}
			resp.Header.Add("Set-Cookie", cookie.String())
			return nil, resp
		},
	)

	logs.Info("Listening on %s", ctx.String("listen"))
	log.Fatal(http.ListenAndServe(ctx.String("listen"), proxy))

	return nil
}
