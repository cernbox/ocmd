package handlers

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cernbox/ocmd/api"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

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

func PropagateInternalShare(logger *zap.Logger, sm api.ShareManager, pa api.ProviderAuthorizer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		shareID := r.FormValue("shareID")

		share, err := sm.GetInternalShare(ctx, shareID)
		if err != nil {
			logger.Error("Error getting share", zap.Error(err))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			ae := api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("Could not retrieve share ID")
			w.Write(ae.JSON())
			return
		}

		domain := getDomainFromMail(share.ShareWith)
		providerInfo, err := pa.GetProviderInfoByDomain(ctx, domain)
		if err != nil {
			logger.Error("error getting provider info", zap.String("input-domain", domain), zap.Error(err))

		}
		logger.Info("provider info", zap.String("domain", providerInfo.Domain), zap.String("ocm-endpoint", providerInfo.APIEndPoint))

		reqBody := bytes.NewReader(share.JSON())
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := http.Client{Transport: tr}
		req, err := http.NewRequest("POST", providerInfo.APIEndPoint+"/shares", reqBody)
		if err != nil {
			logger.Error("error preparing outgoing request for new share", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			logger.Error("Error trying to post share to provider endpoint", zap.Error(err))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			ae := api.NewAPIError(api.APIErrorProviderError).WithMessage("Remote OCM endpoint not reachable")
			w.Write(ae.JSON())
			return
		}
		if resp.StatusCode != http.StatusCreated {
			body, _ := ioutil.ReadAll(resp.Body)
			logger.Error("wrong status code from ocm endpoint", zap.Int("expected", http.StatusCreated), zap.Int("got", resp.StatusCode), zap.String("body", string(body)))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			ae := api.NewAPIError(api.APIErrorProviderError).WithMessage("Wrong status code from OCM endpoint")
			w.Write(ae.JSON())
			return

		}

		logger.Debug("consumer share has been created on the remote OCM instance")

		w.WriteHeader(http.StatusCreated)
		w.Write(share.JSON())
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

func GetOCMInfo(logger *zap.Logger, host string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		info := &api.Info{
			Enabled:    true,
			APIVersion: "1.0-proposal1",
			EndPoint:   fmt.Sprintf("https://%s/cernbox/ocm", host),
			ShareTypes: []api.ShareTypes{api.ShareTypes{
				Name: "file",
				Protocols: api.ShareTypesProtocols{
					Webdav: fmt.Sprintf("https://%s/cernbox/ocm_webdav", host),
				},
			}},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(info.JSON())

	})
}

func AddProvider(logger *zap.Logger, pa api.ProviderAuthorizer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if err := r.ParseForm(); err != nil {
			logger.Error("Error parsing request", zap.Error(err))
			return
		}

		domain := r.FormValue("domain")

		//TODO error if empty

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}

		url := fmt.Sprintf("https://%s/ocm-provider/", domain)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		res, err := client.Do(req)
		if err != nil {
			logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if res.StatusCode != http.StatusOK {
			logger.Error("Error getting provider info", zap.Int("status", res.StatusCode))
			w.WriteHeader(res.StatusCode)
			return
		}

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			logger.Error("Error reading body", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		apiInfo := &api.Info{}
		err = json.Unmarshal(body, apiInfo)
		if err != nil {
			logger.Error("Error parsing provider info", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		internalProvider := &api.ProviderInfo{
			Domain:         domain,
			APIVersion:     apiInfo.APIVersion,
			APIEndPoint:    apiInfo.EndPoint,
			WebdavEndPoint: apiInfo.ShareTypes[0].Protocols.Webdav, //TODO check this instead of hardcode + support for multiple webdav
		}

		pa.AddProvider(ctx, internalProvider)
		w.WriteHeader(http.StatusOK)

	})
}

func AddShare(logger *zap.Logger, sm api.ShareManager, pa api.ProviderAuthorizer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ctx := r.Context()

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			logger.Error("error reading body of the request", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// logger.Info("POST >>>", zap.String("BODY", string(body)))

		share := &api.Share{}
		err = json.Unmarshal(body, share)
		if err != nil {
			logger.Error("error unmarshaling body into share, trying again", zap.Error(err))

			// OC send providerId as int....
			type Share2 struct {
				ShareWith         string            `json:"shareWith"`
				Name              string            `json:"name"`
				Description       string            `json:"description"`
				ProviderID        int               `json:"providerId"`
				Owner             string            `json:"owner"`
				Sender            string            `json:"sender"`
				OwnerDisplayName  string            `json:"ownerDisplayName"`
				SenderDisplayName string            `json:"senderDisplayName"`
				ShareType         string            `json:"shareType"`
				ResourceType      string            `json:"resourceType"`
				Protocol          *api.ProtocolInfo `json:"protocol"`

				ID        string `json:"id,omitempty"`
				CreatedAt string `json:"createdAt,omitempty"`
			}
			share2 := &Share2{}
			err = json.Unmarshal(body, share2)

			if err != nil {
				logger.Error("error unmarshaling body into share", zap.Error(err))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				ae := api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("body is not json")
				w.Write(ae.JSON())
				return
			}

			share = &api.Share{
				ShareWith:         share2.ShareWith,
				Name:              share2.Name,
				Description:       share2.Description,
				ProviderID:        strconv.Itoa(share2.ProviderID),
				Owner:             share2.Owner,
				Sender:            share2.Sender,
				OwnerDisplayName:  share2.OwnerDisplayName,
				SenderDisplayName: share2.SenderDisplayName,
				ShareType:         share2.ShareType,
				ResourceType:      share2.ResourceType,
				Protocol:          share2.Protocol,
				ID:                share2.ID,
				CreatedAt:         share2.CreatedAt,
			}

		}

		logger.Debug("received share from client", zap.String("share", fmt.Sprintf("%+v", share)))

		// OC sends this with http.....
		share.Owner = strings.Replace(share.Owner, "http://", "", 1)
		share.Owner = strings.Replace(share.Owner, "https://", "", 1)
		share.Sender = strings.Replace(share.Sender, "http://", "", 1)
		share.Sender = strings.Replace(share.Sender, "https://", "", 1)

		owner := strings.Split(share.Owner, "@")

		if len(owner) != 2 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			ae := api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("owner must contain domain")
			w.Write(ae.JSON())
			return
		}

		domain := owner[1]

		if err = pa.IsProviderAllowed(ctx, domain); err != nil {
			logger.Debug("Unauthorized owner of share", zap.String("owner", share.Owner), zap.String("domain", domain))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			ae := api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("owner domain is not allowed")
			w.Write(ae.JSON())
			return
		}

		shareWith := strings.Split(share.ShareWith, "@")
		//TODO check user exists and domain valid, possibly get username if email was given !!!

		newShare, err := sm.NewShare(ctx, share, domain, shareWith[0])
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

		w.WriteHeader(http.StatusCreated)
		w.Write(newShare.JSON())

	})
}

func ProxyWebdav(logger *zap.Logger, sm api.ShareManager, pa api.ProviderAuthorizer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// user, _, ok := r.BasicAuth()
		// if !ok {
		// 	logger.Debug("No auth")
		// 	w.WriteHeader(http.StatusForbidden)
		// 	return
		// }
		// With oauth we receive a header with username
		user := r.Header.Get("Remote-User")

		requestPath := mux.Vars(r)["path"]
		logger.Info("WEBDAV PROXY", zap.String("user", user), zap.String("path", requestPath))

		logRequest(logger, r)

		pathElements := strings.FieldsFunc(requestPath, getSplitFunc('/'))

		if len(pathElements) == 0 {

			if r.Method == "OPTIONS" {

				w.Header().Set("dav", "1,2")
				w.Header().Set("allow", "OPTIONS,PROPFIND")

			} else if r.Method == "PROPFIND" {

				bodyb, _ := ioutil.ReadAll(r.Body)
				body := string(bodyb)

				shares, _ := sm.GetShares(ctx, user)

				toReturn := "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
					"<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">"

				toReturn = toReturn + "<d:response>" +
					"<d:href>/cernbox/desktop/remote.php/webdav/ocm/</d:href>" +
					"<d:propstat>" +
					"<d:status>HTTP/1.1 200 OK</d:status>" +
					"<d:prop>"

				if strings.Contains(body, "getlastmodified") {
					toReturn = toReturn + fmt.Sprintf("<d:getlastmodified>%s</d:getlastmodified>", time.Now().Format(time.RFC1123))
				}

				if strings.Contains(body, "creationdate") {
					toReturn = toReturn + "<d:creationdate>2018-12-18T00:00:00Z</d:creationdate>"
				}

				if strings.Contains(body, "getetag") {
					toReturn = toReturn + fmt.Sprintf("<d:getetag>&quot;60:%s&quot;</d:getetag>", string(rand.Intn(100)))
				}

				if strings.Contains(body, "oc:id") {
					toReturn = toReturn + "<oc:id>0</oc:id>"
				}

				if strings.Contains(body, "size") {
					toReturn = toReturn + "<oc:size>2</oc:size>"
				}

				if strings.Contains(body, "permissions") {
					toReturn = toReturn + "<oc:permissions>RWCKNVD</oc:permissions>"
				}

				if strings.Contains(body, "displayname") {
					toReturn = toReturn + "<d:displayname>ocm</d:displayname>"
				}

				toReturn = toReturn + "<d:resourcetype>" +
					"<d:collection/>" +
					"</d:resourcetype>" +
					"</d:prop>" +
					"</d:propstat>" +
					"<d:propstat>" +
					"<d:status>HTTP/1.1 404 Not Found</d:status>" +
					"<d:prop/>" +
					"</d:propstat>" +
					"</d:response>"

				type shareXML struct {
					Name string
					XML  string
				}

				sharesXML := []*shareXML{}

				for i := 0; i < len(shares); i++ {

					name := shares[i].Name
					name = strings.Replace(name, "/", "", 1)
					name = name + " (id-" + shares[i].ID + ")"
					nameURL, _ := url.Parse(name)
					name = nameURL.EscapedPath()

					xml := fmt.Sprintf("<d:response>"+
						"<d:href>/cernbox/desktop/remote.php/webdav/ocm/%s/</d:href>"+
						"<d:propstat>"+
						"<d:status>HTTP/1.1 200 OK</d:status>"+
						"<d:prop>", name)

					if strings.Contains(body, "getlastmodified") {
						xml = xml + fmt.Sprintf("<d:getlastmodified>%s</d:getlastmodified>", time.Now().Format(time.RFC1123))
					}

					if strings.Contains(body, "creationdate") {
						xml = xml + fmt.Sprintf("<d:creationdate>%s</d:creationdate>", shares[i].CreatedAt)
					}

					if strings.Contains(body, "getetag") {
						xml = xml + fmt.Sprintf("<d:getetag>&quot;60:%s:%s&quot;</d:getetag>", shares[i].ID, string(rand.Intn(100)))
					}

					if strings.Contains(body, "oc:id") {
						xml = xml + fmt.Sprintf("<oc:id>%s</oc:id>", shares[i].ID)
					}

					if strings.Contains(body, "size") {
						xml = xml + "<oc:size>2</oc:size>"
					}

					if strings.Contains(body, "permissions") {
						xml = xml + "<oc:permissions>RWCKNVD</oc:permissions>"
					}

					if strings.Contains(body, "displayname") {
						xml = xml + fmt.Sprintf("<d:displayname>%s</d:displayname>", name)
					}

					xml = xml + "<d:resourcetype>" +
						"<d:collection/>" +
						"</d:resourcetype>" +
						"</d:prop>" +
						"</d:propstat>" +
						"<d:propstat>" +
						"<d:status>HTTP/1.1 404 Not Found</d:status>" +
						"<d:prop/>" +
						"</d:propstat>" +
						"</d:response>"

					sharesXML = append(sharesXML, &shareXML{
						Name: name,
						XML:  xml,
					})
				}

				sort.Slice(sharesXML, func(i, j int) bool {
					return sharesXML[i].Name < sharesXML[j].Name
				})

				for i := 0; i < len(sharesXML); i++ {
					toReturn = toReturn + sharesXML[i].XML
				}

				toReturn = toReturn + "</d:multistatus>"
				bToReturn := []byte(toReturn)
				w.Header().Set("Content-Type", "application/xml; charset=utf-8")
				w.Header().Set("Content-Length", strconv.Itoa(len(bToReturn)))
				w.WriteHeader(http.StatusMultiStatus)
				w.Write(bToReturn)

			} else {
				w.WriteHeader(http.StatusForbidden)
			}

		} else {

			currentShareName := pathElements[0]

			shareIDElements := strings.Split(currentShareName, "(id-")
			shareID := shareIDElements[len(shareIDElements)-1]
			shareID = strings.Replace(shareID, ")", "", 1)

			share, err := sm.GetExternalShare(ctx, user, shareID)

			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			providerElements := strings.Split(share.Owner, "@")

			provider, err := pa.GetProviderInfoByDomain(ctx, providerElements[1])

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			replaceLocalPath := fmt.Sprintf("/cernbox/desktop/remote.php/webdav/ocm/%s", currentShareName)
			replaceLocalPathURL, _ := url.Parse(replaceLocalPath)
			replaceLocalPathURLEscaped := replaceLocalPathURL.EscapedPath()

			remotePath := strings.Join(pathElements[1:], "/")
			remoteURL, _ := url.Parse(strings.Replace(path.Join(provider.WebdavEndPoint, remotePath), "https:/", "https://", 1))

			replaceRemotePathURL, _ := url.Parse(provider.WebdavEndPoint)
			replaceRemotePath := replaceRemotePathURL.Path
			replaceRemotePathElems := strings.Split(replaceRemotePath, "/")
			replaceRemotePath = "/" + strings.Join(replaceRemotePathElems[1:], "/")

			replaceRemotePathURL, _ = url.Parse(replaceRemotePath)
			replaceRemotePathURLEscaped := replaceRemotePathURL.EscapedPath()

			logger.Info("INFO", zap.String("remotePath", remotePath), zap.String("remoteURL", remoteURL.String()), zap.String("replaceRemotePath", replaceRemotePathURLEscaped))

			http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			proxy := httputil.NewSingleHostReverseProxy(remoteURL)

			// CHECK OTHER METHODS
			if r.Method == "PROPFIND" {
				proxy.ModifyResponse = rewriteHref(logger, replaceRemotePathURLEscaped, replaceLocalPathURLEscaped)
			} else if r.Method == "MOVE" {
				destination := r.Header.Get("destination")
				destinationElems := strings.Split(destination, replaceLocalPathURLEscaped)
				destinationURL, _ := url.Parse(strings.Replace(path.Join(provider.WebdavEndPoint, destinationElems[1]), "https:/", "https://", 1))
				// logger.Info("INFO", zap.String("DESTINATION", destinationURL.String()))
				r.Header.Set("destination", destinationURL.String())
			}

			r.URL, _ = url.Parse("")
			r.Host = remoteURL.Host
			r.SetBasicAuth(share.Protocol.Options.SharedSecret, share.Protocol.Options.SharedSecret)

			proxy.ServeHTTP(w, r)

		}

	})
}

func getSplitFunc(separator rune) func(rune) bool {
	return func(c rune) bool {
		return c == separator
	}
}

func rewriteHref(logger *zap.Logger, oldPath, newPath string) func(resp *http.Response) (err error) {
	return func(resp *http.Response) (err error) {

		if resp.StatusCode == 401 || (resp.StatusCode >= 300 && resp.StatusCode < 400) {
			// If the sharer revoked the share, we shouldn't make our users login again
			// If we got a redirect, we shouldn't follow it for security reasons
			resp.StatusCode = 404
			return nil
		}

		contentType := resp.Header.Get("Content-type")
		if !strings.Contains(contentType, "application/xml") {
			return nil
		}

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		err = resp.Body.Close()
		if err != nil {
			return err
		}
		b = bytes.Replace(b, []byte(oldPath), []byte(newPath), -1) // replace html
		body := ioutil.NopCloser(bytes.NewReader(b))
		resp.Body = body
		resp.ContentLength = int64(len(b))
		resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
		return nil
	}
}

func logRequest(logger *zap.Logger, r *http.Request) {

	// Create return string
	var request []string
	// Add the request string
	my_url := fmt.Sprintf("%v %v %v", r.Method, r.URL, r.Proto)
	request = append(request, my_url)
	// Add the host
	request = append(request, fmt.Sprintf("Host: %v", r.Host))
	// Loop through headers
	for name, headers := range r.Header {
		name = strings.ToLower(name)
		for _, h := range headers {
			request = append(request, fmt.Sprintf("%v: %v", name, h))
		}
	}

	// If this is a POST, add post data
	if r.Method == "POST" {
		r.ParseForm()
		request = append(request, "\n")
		request = append(request, r.Form.Encode())
	}

	logger.Info("REQUEST ", zap.String(r.Method, strings.Join(request, " +++ ")))
}
