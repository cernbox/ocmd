package provider_authorizer_memory

import (
	"context"
	"fmt"
	"strings"

	"github.com/cernbox/ocmd/api"
)

type providerAuthorizer struct {
	allowedProviders []string
}

func New(providersString string) api.ProviderAuthorizer {
	fmt.Println(providersString)
	providers := strings.Split(providersString, ",")
	pa := &providerAuthorizer{allowedProviders: providers}
	return pa
}

func (pa *providerAuthorizer) IsProviderAllowed(ctx context.Context, providerID string) error {
	for _, p := range pa.allowedProviders {
		if p == providerID {
			fmt.Println(p, providerID)
			return nil
		}
	}
	return api.NewAPIError(api.APIErrorUntrustedService)
}
