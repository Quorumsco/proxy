package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"runtime"
	"strings"

	"gopkg.in/redis.v3"

	"github.com/codegangsta/cli"
	"github.com/elazarl/goproxy"
	"github.com/pborman/uuid"
	"github.com/quorumsco/cmd"
	"github.com/quorumsco/logs"
	"github.com/quorumsco/proxy/components"
	"github.com/quorumsco/settings"
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
		cli.StringFlag{Name: "client-id", Value: "proxy", Usage: "oauth2 proxy client id", EnvVar: "CLIENT_ID"},
		cli.StringFlag{Name: "client-secret", Value: "proxy", Usage: "oauth2 proxy client secret", EnvVar: "CLIENT_SECRET"},

		cli.StringFlag{Name: "config, c", Usage: "configuration file", EnvVar: "CONFIG"},
		cli.BoolFlag{Name: "debug, d", Usage: "print debug information"},
		cli.HelpFlag,
	}...)
	cmd.RunAndExitOnError()
}

func serve(ctx *cli.Context) error {
	clientID := ctx.String("client-id")
	clientSecret := ctx.String("client-secret")

	config, err := settings.Parse(ctx.String("config"))
	if err != nil && ctx.String("config") != "" {
		logs.Error(err)
	}

	if ctx.Bool("debug") || config.Debug() {
		logs.Level(logs.DebugLevel)
	}

	redisSettings, err := config.Redis()
	client := redis.NewClient(&redis.Options{Addr: redisSettings.String()})
	if _, err := client.Ping().Result(); err != nil {
		return err
	}
	logs.Debug("Connected to Redis at %s", redisSettings.String())
	store := components.NewRedisStore(client)

	proxy := goproxy.NewProxyHttpServer()
	if ctx.Bool("debug") || config.Debug() {
		proxy.Verbose = true
	}

	// Treat only requests with an SID cookie or POSTing username and password.
	var session = goproxy.ReqConditionFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) bool {
		_, err := req.Cookie("SID")
		return err == nil || (req.Method == "POST" && req.FormValue("username") != "" && req.FormValue("password") != "") // The form is already parsed.
	})

	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		dump, _ := httputil.DumpRequest(req, true)
		fmt.Println(string(dump))
		req.URL.Scheme = req.Header.Get("X-Scheme")
		req.URL.Host = req.Host
		proxy.ServeHTTP(w, req)
	})

	proxy.OnRequest(session).DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			//dump, _ := httputil.DumpRequest(req, true)
			//fmt.Println(string(dump))
			cookie, err := req.Cookie("SID")
			if err == nil {
				session, err := store.Load(cookie.Value)
				if err != nil {
					return req, goproxy.NewResponse(req, "text/plain", http.StatusForbidden, "Invalid cookie")
				}
				req.Header.Del("Cookie")
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

			//req.RequestURI = "" // Must be removed for client requests
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				return req, nil
			}
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return req, nil
			}

			// TODO: Check http status for errors
			access := new(components.AccessData)
			if err := json.Unmarshal(body, access); err != nil {
				return req, nil
			}
			session := &components.Session{
				ID:           strings.TrimRight(base64.StdEncoding.EncodeToString(uuid.NewRandom()), "="),
				AccessToken:  access.AccessToken,
				RefreshToken: access.RefreshToken,
				ExpiresIn:    access.ExpiresIn,
			}
			if err := store.Save(session); err != nil {
				return req, nil
			}

			// TODO: Give a json response to clients
			resp = goproxy.NewResponse(req, "text/plain", http.StatusOK, "")
			cookie = &http.Cookie{Name: "SID", Value: session.ID}
			resp.Header.Add("Set-Cookie", cookie.String())
			return req, resp
		},
	)
	server, err := config.Server()
	if err != nil {
		logs.Critical(err)
		os.Exit(1)
	}
	logs.Info("Listening on %s", server.String())
	return http.ListenAndServe(server.String(), proxy)
}
