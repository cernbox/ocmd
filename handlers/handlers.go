package handlers

import (
	"bytes"
	"crypto/tls"
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

// TODO(labkode): Read Remote-User header? that is forwarded by Shibboleth, like swanapid
func SSOAuthCheck(logger *zap.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// identity examples: hugo@localhost, caty@airbus.com
		identity := r.Header.Get("Remote-User")
		if identity == "" {
			logger.Error("SSO auth credentials are empty, configure SSO correctly")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		mux.Vars(r)["identity"] = identity
		logger.Info("SSO auth ok", zap.String("identity", identity))
		h.ServeHTTP(w, r)
	})
}

func TrustedDomainCheck(logger *zap.Logger, providerAuthorizer api.ProviderAuthorizer, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		remoteAddress := r.RemoteAddr // ip:port
		clientIP := strings.Split(remoteAddress, ":")[0]
		domains, err := net.LookupAddr(clientIP)
		if err != nil {
			logger.Error("error getting domain for IP", zap.Error(err))
			w.WriteHeader(http.StatusForbidden)
			ae := api.NewAPIError(api.APIErrorUntrustedService)
			w.Write(ae.JSON())
			return
		}
		logger.Debug("ip resolution", zap.String("ip", clientIP), zap.String("remote-address", remoteAddress), zap.String("domains", fmt.Sprintf("%+v", domains)))

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

		logger.Debug("hal_share to send to client", zap.String("hal_share", fmt.Sprintf("%+v", hal_share)))

		w.Header().Set("Location", hal_links.Self.Href)
		w.WriteHeader(http.StatusCreated)
		w.Write(hal_share.JSON())
	})

}

// NewInternalShare creates a new remote OCM share.
// This process is a 3-way phase commit between two OCM instances.
// 1. The internal user triggers a request to share with another OCM instance. This internal share is stored but not visible.
// 2. The request is sent to the other OCM instance, which replies with its internal share ID to consult after.
// 3. Update the internal share with the provider ID.
func NewInternalShare(logger *zap.Logger, ism api.InternalShareManager, pa api.ProviderAuthorizer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		identity := mux.Vars(r)["identity"] // owner of the shared resources: hugo@localhost

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			logger.Error("error reading body of the request", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		params := &api.Share{}
		err = json.Unmarshal(body, params)
		if err != nil {
			logger.Error("error unmarshaling body into share", zap.Error(err))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			ae := api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("body is not json")
			w.Write(ae.JSON())
			return
		}

		params.Protocol.Name = "webdav" // ocmd only implements webdav.
		params.Owner = identity
		logger.Debug("input share from internal user", zap.String("share", fmt.Sprintf("%+v", params)))

		internalShare, err := ism.NewInternalShare(ctx, params)
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

		logger.Debug("internal share has now a providerId, ready to sent to remote OCM provider", zap.String("share", fmt.Sprintf("%+v", internalShare)))

		domain := getDomainFromMail(internalShare.ShareWith)
		providerInfo, err := pa.GetProviderInfoByDomain(ctx, domain)
		if err != nil {
			logger.Error("error getting provider info", zap.String("input-domain", domain), zap.Error(err))

		}
		logger.Info("provider info", zap.String("domain", providerInfo.Domain), zap.String("ocm-endpoint", providerInfo.URL.String()))

		reqBody := bytes.NewReader(internalShare.JSON())
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := http.Client{Transport: tr}
		req, err := http.NewRequest("POST", providerInfo.URL.String()+"/shares", reqBody)
		if err != nil {
			logger.Error("error preparing outgoing request for new share", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		resp, err := client.Do(req)
		if err != nil {
			logger.Error("error executing the request", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if resp.StatusCode != http.StatusCreated {
			logger.Error("wrong status code from ocm endpoint", zap.Int("expected", http.StatusCreated), zap.Int("got", resp.StatusCode))
			w.WriteHeader(http.StatusInternalServerError)
			return

		}
		// unmarshal response in ocm share
		consumerShare := &api.Share{}
		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			logger.Error("error reading body of the request", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		err = json.Unmarshal(body, consumerShare)
		if err != nil {
			logger.Error("error unmarshaling body into share", zap.Error(err))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			ae := api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("body is not json")
			w.Write(ae.JSON())
			return
		}

		logger.Debug("consumer share has been created on the remote OCM instance", zap.String("consumer-share", fmt.Sprintf("%+v", consumerShare)))

		internalShare, err = ism.CommitInternalShare(ctx, internalShare.ProviderID, consumerShare.ID)
		if err != nil {
			logger.Error("error commiting share", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Write(internalShare.JSON())
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

func getDomainFromMail(mail string) string {
	tokens := strings.Split(mail, "@")
	return tokens[len(tokens)-1]

}
