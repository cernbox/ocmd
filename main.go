package main

import (
	"net/http"
	"time"

	"github.com/cernbox/gohub/goconfig"
	"github.com/cernbox/gohub/gologger"
	"github.com/cernbox/ocmd/api"
	"github.com/cernbox/ocmd/api/provider_manager_mysql"
	"github.com/cernbox/ocmd/api/share_manager_mysql"
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

	gc.Add("host", "localhost", "Base hostname of this service")

	gc.Add("mysql-hostname", "localhost", "MySQL server hostname.")
	gc.Add("mysql-port", 3306, "MySQL server port.")
	gc.Add("mysql-username", "root", "MySQL server username.")
	gc.Add("mysql-password", "", "MySQL server password.")
	gc.Add("mysql-db", "cbox", "DB name.")
	gc.Add("mysql-table", "oc_share", "Table name.")

	gc.BindFlags()
	gc.ReadConfig()

	logger := gologger.New(gc.GetString("log-level"), gc.GetString("app-log"))

	opt := &api.MySQLOptions{
		Hostname: gc.GetString("mysql-hostname"),
		Port:     gc.GetInt("mysql-port"),
		Username: gc.GetString("mysql-username"),
		Password: gc.GetString("mysql-password"),
		DB:       gc.GetString("mysql-db"),
		Table:    gc.GetString("mysql-table"),
		Logger:   logger,
	}
	shareManager := share_manager_mysql.New(gc.GetString("host"), opt)
	providerAuthorizer := provider_manager_mysql.New(opt)

	router := mux.NewRouter()

	getOCMInfoHandler := handlers.GetOCMInfo(logger, gc.GetString("host"))
	//TODO enable trusted domain check
	// addShareHandler := handlers.TrustedDomainCheck(logger, providerAuthorizer, handlers.AddShare(logger, shareManager))
	addShareHandler := handlers.AddShare(logger, shareManager, providerAuthorizer)
	proxyWebdavHandler := handlers.ProxyWebdav(logger, shareManager, providerAuthorizer)

	// Endpoints as consumer, someone call us and we are compliant with OCM.
	router.Handle("/ocm/ocm-provider/", getOCMInfoHandler).Methods("GET")
	router.Handle("/ocm/shares", addShareHandler).Methods("POST")
	router.Handle("/ocm/notifications", handlers.NotImplemented(logger)).Methods("GET")
	router.Handle("/ocm/notifications/{}", handlers.NotImplemented(logger)).Methods("GET")
	router.Handle("/ocm/notifications", handlers.NotImplemented(logger)).Methods("POST")

	router.Handle("/ocm/webdav{path:.*}", proxyWebdavHandler)

	// Internal endpoints
	propagationShareHandler := handlers.PropagateInternalShare(logger, shareManager, providerAuthorizer)
	addProviderHandler := handlers.AddProvider(logger, providerAuthorizer)

	router.Handle("/internal/shares", propagationShareHandler).Methods("POST")
	router.Handle("/internal/providers", addProviderHandler).Methods("POST")

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
