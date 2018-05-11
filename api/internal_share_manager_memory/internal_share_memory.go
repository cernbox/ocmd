package internal_share_manager_memory

import (
	"context"
	"fmt"
	"github.com/cernbox/ocmd/api"
	"sync"
	"time"
)

type internalShareManager struct {
	sync.RWMutex
	shares []*api.Share
	um     api.UserManager
}

func New(userManager api.UserManager) api.InternalShareManager {
	ism := &internalShareManager{
		shares: []*api.Share{},
		um:     userManager,
	}
	return ism
}

func (ism *internalShareManager) NewInternalShare(ctx context.Context, share *api.Share) (*api.Share, error) {
	err := ism.validateShare(ctx, share)
	if err != nil {
		return nil, err
	}
	ism.Lock()
	defer ism.Unlock()

	newID := fmt.Sprintf("%d", len(ism.shares))
	share.ID = "" // filled in the commit phase
	share.ProviderID = newID
	share.CreatedAt = time.Now().Format("2006-01-02T15:04:05-0700")

	ism.shares = append(ism.shares, share)
	return share, nil
}

func (ism *internalShareManager) CommitInternalShare(ctx context.Context, providerID, consumerID string) (*api.Share, error) {
	internalShare := ism.getByProviderID(providerID)
	if internalShare == nil {
		return nil, api.NewAPIError(api.APIErrorNotFound)
	}

	ism.Lock()
	defer ism.Unlock()
	internalShare.ID = consumerID
	return internalShare, nil
}
func (ism *internalShareManager) getByProviderID(id string) *api.Share {
	ism.Lock()
	defer ism.Unlock()

	for _, share := range ism.shares {
		if share.ProviderID == id {
			return share
		}
	}
	return nil
}

func (s *internalShareManager) validateShare(ctx context.Context, share *api.Share) error {
	if share.ShareWith == "" {
		return api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("shareWith")
	} else if share.Name == "" {
		return api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("name")
	} else if share.Owner == "" {
		return api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("owner")
	} else if share.Protocol == nil {
		return api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("protocol")
	} else if share.Protocol.Name == "" {
		return api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("protocol.name")
	} else if share.Protocol.Options == nil {
		return api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("protocol.options")
	} else {
		return nil
	}

}
