package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"go.uber.org/zap"
)

type APIErrorCode string

const (
	APIErrorNotFound         APIErrorCode = "RESOURCE_NOT_FOUND"
	APIErrorUnauthenticated  APIErrorCode = "UNAUTHENTICATED"
	APIErrorUntrustedService APIErrorCode = "UNTRUSTED_SERVICE"
	APIErrorUnimplemented    APIErrorCode = "FUNCTION_NOT_IMPLEMENTED"
	APIErrorInvalidParameter APIErrorCode = "INVALID_PARAMETER"
	APIErrorProviderError    APIErrorCode = "PROVIDER_ERROR"
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

type Share struct {
	ShareWith         string        `json:"shareWith"`
	Name              string        `json:"name"`
	Description       string        `json:"description"`
	ProviderID        string        `json:"providerId"`
	Owner             string        `json:"owner"`
	Sender            string        `json:"sender"`
	OwnerDisplayName  string        `json:"ownerDisplayName"`
	SenderDisplayName string        `json:"senderDisplayName"`
	ShareType         string        `json:"shareType"`
	ResourceType      string        `json:"resourceType"`
	Protocol          *ProtocolInfo `json:"protocol"`

	ID        string `json:"id,omitempty"`
	CreatedAt string `json:"createdAt,omitempty"`
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
	SharedSecret string `json:"sharedSecret,omitempty"`
	Permissions  string `json:"permissions,omitempty"`
}

type UserManager interface {
	UserExists(ctx context.Context, username string) error
}

type ProviderAuthorizer interface {
	IsProviderAllowed(ctx context.Context, domain string) error
	GetProviderInfoByDomain(ctx context.Context, domain string) (*ProviderInfo, error)
	AddProvider(ctx context.Context, p *ProviderInfo) error
}

type ProviderInfo struct {
	Domain         string
	APIVersion     string
	APIEndPoint    string
	WebdavEndPoint string
}

type ShareManager interface {
	GetInternalShare(ctx context.Context, id string) (*Share, error)
	NewShare(ctx context.Context, share *Share, domain, shareWith string) (*Share, error)
	GetShares(ctx context.Context, user string) ([]*Share, error)
	GetExternalShare(ctx context.Context, sharedWith, id string) (*Share, error)
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

type MySQLOptions struct {
	Hostname string
	Port     int
	Username string
	Password string
	DB       string
	Table    string

	Logger *zap.Logger
}

type Info struct {
	Enabled       bool            `json:"enabled"`
	APIVersion    string          `json:"apiVersion"`
	EndPoint      string          `json:"endPoint"`
	ResourceTypes []ResourceTypes `json:"resourceTypes"`
}

type ResourceTypes struct {
	Name       string                 `json:"name"`
	ShareTypes []string               `json:"shareTypes"`
	Protocols  ResourceTypesProtocols `json:"protocols"`
}

type ResourceTypesProtocols struct {
	Webdav string `json:"webdav"`
}

func (s *Info) JSON() []byte {
	b, _ := json.MarshalIndent(s, "", "   ")
	return b

}
