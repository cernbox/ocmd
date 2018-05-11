package main

import (
	"net/http"
	"time"

	"github.com/cernbox/gohub/goconfig"
	"github.com/cernbox/gohub/gologger"
	"github.com/cernbox/ocmd/api/provider_authorizer_memory"
	"github.com/cernbox/ocmd/api/share_manager_memory"
	"github.com/cernbox/ocmd/api/user_manager_memory"
	"github.com/cernbox/ocmd/handlers"

	"github.com/facebookgo/grace/gracehttp"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

func main() {

	gc := goconfig.New()
	gc.SetConfigName("ocmd")
	gc.AddConfigurationPaths("/etc/ocmd/")
	gc.Add("tcp-address", "localhost:8888", "tcp address to listen for connections.")
	gc.Add("log-level", "info", "log level to use (debug, info, warn, error).")
	gc.Add("app-log", "stderr", "file to log application information.")
	gc.Add("http-log", "stderr", "file to log HTTP requests.")
	gc.Add("http-read-timeout", 300, "the maximum duration for reading the entire request, including the body.")
	gc.Add("http-write-timeout", 300, "the maximum duration for timing out writes of the response.")
	gc.Add("python-script-location", "/usr/bin/ocm-share.py", "Location of the python-script to to OCM sharing.")
	gc.Add("sign-secret", "foo", "Secre to use to sign JWT tokens.")
	gc.Add("eos-http-address", "eosuat.cern.ch:8000", "HTTP address of the EOS mgm.")
	gc.Add("user-manager-memory-usernames", "hugo.gonzalez.labrador@cern.ch,moscicki@cern.ch,bocchi@cern.ch", "List of internal users.")
	gc.Add("provider-authorizer-memory-domains", "localhost,labradorbox.cern.ch", "List of trusted OCM instances.")
	gc.BindFlags()
	gc.ReadConfig()

	logger := gologger.New(gc.GetString("log-level"), gc.GetString("app-log"))

	userManager := user_manager_memory.New(gc.GetString("user-manager-memory-usernames"))
	shareManager := share_manager_memory.New(userManager)
	providerAuthorizer := provider_authorizer_memory.New(gc.GetString("provider-authorizer-memory-domains"))

	router := mux.NewRouter()

	router.Handle("/cernbox/ocmwebdav", handlers.WebDAV(logger))

	getAllSharesHandler := handlers.TrustedDomainCheck(logger, providerAuthorizer, handlers.GetAllShares(logger, shareManager))
	getShareByIDHandler := handlers.TrustedDomainCheck(logger, providerAuthorizer, handlers.GetShareByID(logger, shareManager))
	newShareHandler := handlers.TrustedDomainCheck(logger, providerAuthorizer, handlers.NewShare(logger, shareManager))

	router.Handle("/ocm/shares", getAllSharesHandler).Methods("GET")
	router.Handle("/ocm/shares/{id}", getShareByIDHandler).Methods("GET")
	router.Handle("/ocm/shares", newShareHandler).Methods("POST")
	router.Handle("/ocm/notifications", handlers.NotImplemented(logger)).Methods("GET")
	router.Handle("/ocm/notifications/{}", handlers.NotImplemented(logger)).Methods("GET")
	router.Handle("/ocm/notifications", handlers.NotImplemented(logger)).Methods("POST")

	router.Handle("/metrics", promhttp.Handler()) // metrics for the daemon

	loggedRouter := gologger.GetLoggedHTTPHandler(gc.GetString("http-log"), router)

	s := &http.Server{
		Addr:         gc.GetString("tcp-address"),
		ReadTimeout:  time.Second * time.Duration(gc.GetInt("http-read-timeout")),
		WriteTimeout: time.Second * time.Duration(gc.GetInt("http-write-timeout")),
		Handler:      loggedRouter,
	}

	logger.Info("server is listening at: " + gc.GetString("tcp-address"))
	gracehttp.SetLogger(zap.NewStdLog(logger))
	err := gracehttp.Serve(s)
	if err != nil {
		logger.Error("server stop listening with error: " + err.Error())
	} else {
		logger.Info("server stop listening")
	}

}
