package handlers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"

	"github.com/cernbox/ocmd/api"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

func TrustedDomainCheck(logger *zap.Logger, providerAuthorizer api.ProviderAuthorizer, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		remoteAddress := r.RemoteAddr // ip:port
		clientIP := strings.Split(remoteAddress, ":")[0]
		logger.Debug("domain check", zap.String("ip", clientIP), zap.String("remote-address", remoteAddress))
		domains, err := net.LookupAddr(clientIP)
		if err != nil {
			logger.Error("error getting domain for IP", zap.Error(err))
			w.WriteHeader(http.StatusForbidden)
			ae := api.NewAPIError(api.APIErrorUntrustedService)
			w.Write(ae.JSON())
			return
		}

		allowedDomain := ""
		for _, domain := range domains {
			if err := providerAuthorizer.IsProviderAllowed(ctx, domain); err == nil {
				allowedDomain = domain
				break
			}
			logger.Debug("domain not allowed", zap.String("domain", domain))
		}

		if allowedDomain == "" {
			logger.Error("provider is not allowed to use the API", zap.String("remote-address", remoteAddress))
			w.WriteHeader(http.StatusForbidden)
			ae := api.NewAPIError(api.APIErrorUntrustedService)
			w.Write(ae.JSON())
			return
		}

		logger.Debug("provider is allowd to access the API", zap.String("remote-address", remoteAddress), zap.String("domain", allowedDomain))
		mux.Vars(r)["domain"] = allowedDomain
		h.ServeHTTP(w, r)
	})
}

func TokenCheck(logger *zap.Logger, tokenManager api.TokenManager, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		token := r.Header.Get("X-Access-Token")
		if token == "" {
			logger.Info("access token is empty")
			w.WriteHeader(http.StatusUnauthorized)
			ae := api.NewAPIError(api.APIErrorUnauthenticated)
			w.Write(ae.JSON())
			return
		}

		if err := tokenManager.IsValid(ctx, r.URL, token); err != nil {
			logger.Error("access token is invalid", zap.Error(err))
			w.WriteHeader(http.StatusUnauthorized)
			ae := api.NewAPIError(api.APIErrorUnauthenticated)
			w.Write(ae.JSON())
			return
		}
		h.ServeHTTP(w, r)
	})
}

func WebDAV(logger *zap.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})

}

// TODO(labkode): we should only return shares that match the asking provider.
func GetAllShares(logger *zap.Logger, sm api.ShareManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		shares, err := sm.GetShares(ctx)
		if err != nil {
			logger.Error("error getting shares", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return

		}

		hal_shares := []*api.HAL_SingleShareResponse{}
		for _, s := range shares {
			hal_links := &api.HAL_Links{Self: &api.HAL_Ref{Href: fmt.Sprintf("%s/%s", r.URL.String(), s.ID)}}
			hal_share := &api.HAL_SingleShareResponse{Share: s, HAL_Links: hal_links}
			hal_shares = append(hal_shares, hal_share)
		}

		hal_links := &api.HAL_Links{Self: &api.HAL_Ref{Href: r.URL.String()}}
		hal_embbeded := &api.HAL_Embedded{HAL_Shares: hal_shares}
		hal_shares_res := &api.HAL_MultipleShareResponse{Embbeded: hal_embbeded, Links: hal_links}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Page", "0")
		w.Header().Set("X-Per-Page", fmt.Sprintf("%d", len(shares)))
		w.Header().Set("X-Total", fmt.Sprintf("%d", len(shares)))
		w.WriteHeader(http.StatusOK)
		w.Write(hal_shares_res.JSON())
	})

}

func GetShareByID(logger *zap.Logger, sm api.ShareManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		id := mux.Vars(r)["id"]
		if id == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			logger.Error("share not found", zap.String("id", id))
			ae := api.NewAPIError(api.APIErrorNotFound)
			w.Write(ae.JSON())
			return
		}

		share, err := sm.GetShare(ctx, id)
		if err != nil {
			logger.Error("error getting share", zap.Error(err), zap.String("id", id))
			if ae, ok := err.(*api.APIError); ok {
				if ae.Code == api.APIErrorNotFound {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					logger.Error("share not found", zap.String("id", id))
					ae := api.NewAPIError(api.APIErrorNotFound)
					w.Write(ae.JSON())
					return
				}

			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		hal_links := &api.HAL_Links{Self: &api.HAL_Ref{Href: r.URL.String()}}
		hal_share := &api.HAL_SingleShareResponse{Share: share, HAL_Links: hal_links}

		w.WriteHeader(http.StatusOK)
		w.Write(hal_share.JSON())

	})

}

func NewShare(logger *zap.Logger, sm api.ShareManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		domain := mux.Vars(r)["domain"]
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			logger.Error("error reading body of the request", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		share := &api.Share{}
		err = json.Unmarshal(body, share)
		if err != nil {
			logger.Error("error unmarshaling body into share", zap.Error(err))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			ae := api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("body is not json")
			w.Write(ae.JSON())
			return
		}

		share.TrustedService = domain
		share.Incoming = true
		logger.Debug("received share from client", zap.String("share", fmt.Sprintf("%+v", share)))

		newShare, err := sm.NewShare(ctx, share)
		if err != nil {
			logger.Error("error creating share", zap.Error(err))
			if ae, ok := err.(*api.APIError); ok {
				if ae.Code == api.APIErrorInvalidParameter {
					logger.Error("invalid parameters provided for creating share", zap.Error(err))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					w.Write(ae.JSON())
					return

				}
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		hal_links := &api.HAL_Links{Self: &api.HAL_Ref{Href: fmt.Sprintf("%s/%s", r.URL.String(), newShare.ID)}}
		hal_share := &api.HAL_SingleShareResponse{Share: newShare, HAL_Links: hal_links}

		w.Header().Set("Location", hal_links.Self.Href)
		w.WriteHeader(http.StatusCreated)
		w.Write(hal_share.JSON())
	})

}

func NotImplemented(logger *zap.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		apiErr := api.NewAPIError(api.APIErrorUnimplemented)
		w.Write(apiErr.JSON())
	})

}
