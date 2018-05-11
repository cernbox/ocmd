package provider_authorizer_memory

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/cernbox/ocmd/api"
)

type providerAuthorizer struct {
	providerInfos []*api.ProviderInfo
}

// providersString is "airbus.com:https://api.airbus.com/ocm,https://intel.com:api.intel.com/v1/opencloud"
func New(providersString string) api.ProviderAuthorizer {
	infos := []*api.ProviderInfo{}
	tokens := strings.Split(providersString, ",") //
	for _, token := range tokens {
		tkns := strings.Split(token, "::")
		u, err := url.Parse(tkns[1])
		if err != nil {
			panic(err)
		}
		fmt.Println(u)

		infos = append(infos, &api.ProviderInfo{Domain: tkns[0], URL: u})
	}
	return &providerAuthorizer{providerInfos: infos}
}

func (pa *providerAuthorizer) IsProviderAllowed(ctx context.Context, domain string) error {
	_, err := pa.GetProviderInfoByDomain(ctx, domain)
	return err
}

func (pa *providerAuthorizer) GetProviderInfoByDomain(ctx context.Context, domain string) (*api.ProviderInfo, error) {
	pi, err := pa.getByDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	return pi, nil
}

func (pa *providerAuthorizer) ListProviders(ctx context.Context) ([]*api.ProviderInfo, error) {
	return pa.providerInfos, nil
}

func (pa *providerAuthorizer) getByDomain(ctx context.Context, domain string) (*api.ProviderInfo, error) {
	for _, pi := range pa.providerInfos {
		if pi.Domain == domain {
			return pi, nil
		}
	}
	return nil, api.NewAPIError(api.APIErrorUntrustedService)
}
