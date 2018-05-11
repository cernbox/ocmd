package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

type APIErrorCode string

const (
	APIErrorNotFound         APIErrorCode = "RESOURCE_NOT_FOUND"
	APIErrorUnauthenticated  APIErrorCode = "UNAUTHENTICATED"
	APIErrorUntrustedService APIErrorCode = "UNTRUSTED_SERVICE"
	APIErrorUnimplemented    APIErrorCode = "FUNCTION_NOT_IMPLEMENTED"
	APIErrorInvalidParameter APIErrorCode = "INVALID_PARAMETER"
)

func NewAPIError(code APIErrorCode) *APIError {
	return &APIError{Code: code}
}

type APIError struct {
	Code    APIErrorCode `json:"code"`
	Message string       `json:"message"`
}

func (e *APIError) WithMessage(msg string) *APIError {
	e.Message = msg
	return e
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *APIError) JSON() []byte {
	b, _ := json.MarshalIndent(e, "", "    ")
	return b
}

/*
{
  "shareWith": "peter.szegedi@geant.org",
  "name": "spec.yaml",
  "description": "This is the Open API Specification file (in YAML format) of the Open Cloud Mesh API.",
  "providerId": "7c084226-d9a1-11e6-bf26-cec0c932ce01",
  "owner": "dimitri@apiwise.nl",
  "protocol": {
    "name": "webdav",
    "options": {
      "username": "dimitri",
      "permissions": 31
    }
  },
  "id": 3819,
  "createdAt": "2016-12-05T15:06:58Z",
  "_links": {
    "self": {
      "href": "/shares/3819"
    }
  }
}
*/

type Share struct {
	ID          string        `json:"id"`
	CreatedAt   string        `json:"createdAt"`
	ShareWith   string        `json:"shareWith"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	ProviderID  string        `json:"providerId"`
	Owner       string        `json:"owner"`
	Protocol    *ProtocolInfo `json:"protocol"`

	// TrustedService stores the identity (domain) of the service that can send shares to our users.
	TrustedService string `json:"trustedService"`
}

func (s *Share) JSON() []byte {
	b, _ := json.MarshalIndent(s, "", "   ")
	return b

}

type ProtocolInfo struct {
	Name    string           `json:"name"`
	Options *ProtocolOptions `json:"options"`
}

type ProtocolOptions struct {
	URI         string `json:"uri,omitempty"`
	AccessToken string `json:"access_token,omitempty"`
	Username    string `json:"username,omitempty"`
	Permissions string `json:"permissions,omitempty"`
}

type UserManager interface {
	UserExists(ctx context.Context, username string) error
}

type ProviderAuthorizer interface {
	ListProviders(ctx context.Context) ([]*ProviderInfo, error)
	IsProviderAllowed(ctx context.Context, domain string) error
	GetProviderInfoByDomain(ctx context.Context, domain string) (*ProviderInfo, error)
}

type ProviderInfo struct {
	Domain string
	URL    *url.URL
}

type ShareManager interface {
	GetShare(ctx context.Context, id string) (*Share, error)
	GetShares(ctx context.Context) ([]*Share, error)
	NewShare(ctx context.Context, share *Share) (*Share, error)
}

type InternalShareManager interface {
	NewInternalShare(ctx context.Context, share *Share) (*Share, error)
	CommitInternalShare(ctx context.Context, providerID, consumerID string) (*Share, error)
}

type TokenManager interface {
	IsValid(ctx context.Context, u *url.URL, token string) error
}

// HAL mambo-jambo for the format of the responses.
type HAL_Links struct {
	Self *HAL_Ref `json:"self"`
	Next *HAL_Ref `json:"next,omitempty"`
}

type HAL_Ref struct {
	Href string `json:"href"`
}

type HAL_Embedded struct {
	HAL_Shares []*HAL_SingleShareResponse `json:"shares"`
}

type HAL_SingleShareResponse struct {
	*Share
	*HAL_Links `json:"_links"`
}

func (ssr HAL_SingleShareResponse) JSON() []byte {
	b, _ := json.MarshalIndent(ssr, "", "   ")
	return b
}

type HAL_MultipleShareResponse struct {
	Embbeded *HAL_Embedded `json:"_embbeded"`
	Links    *HAL_Links    `json:"_links"`
}

func (msr HAL_MultipleShareResponse) JSON() []byte {
	b, _ := json.MarshalIndent(msr, "", "   ")
	return b
}
