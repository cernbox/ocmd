package share_manager_memory

import (
	"context"
	"fmt"
	"github.com/cernbox/ocmd/api"
	"sync"
	"time"
)

type shareManager struct {
	sync.RWMutex
	shares []*api.Share
	um     api.UserManager
}

func New(userManager api.UserManager) api.ShareManager {
	sm := &shareManager{
		shares: []*api.Share{},
		um:     userManager,
	}
	return sm
}

func (sm *shareManager) GetShare(ctx context.Context, id string) (*api.Share, error) {
	s := sm.getByID(id)
	if s != nil {
		return s, nil
	}
	return nil, api.NewAPIError(api.APIErrorNotFound)
}

func (sm *shareManager) GetShares(ctx context.Context) ([]*api.Share, error) {
	return sm.shares, nil
}

func (sm *shareManager) NewShare(ctx context.Context, share *api.Share) (*api.Share, error) {
	err := sm.validateShare(ctx, share)
	if err != nil {
		return nil, err
	}
	sm.Lock()
	sm.Unlock()

	newID := fmt.Sprintf("%d", len(sm.shares))
	share.ID = newID
	share.CreatedAt = time.Now().Format("2006-01-02T15:04:05-0700")

	sm.shares = append(sm.shares, share)
	return share, nil
}

func (sm *shareManager) getByID(id string) *api.Share {
	sm.Lock()
	defer sm.Unlock()

	for _, share := range sm.shares {
		if share.ID == id {
			return share
		}
	}
	return nil
}

func (s *shareManager) validateShare(ctx context.Context, share *api.Share) error {
	if share.ShareWith == "" {
		return api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("shareWith")
	} else if share.Name == "" {
		return api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("name")
	} else if share.ProviderID == "" {
		return api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("providerId")
	} else if share.Owner == "" {
		return api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("owner")
	} else if share.Protocol == nil {
		return api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("protocol")
	} else if share.Protocol.Name == "" {
		return api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("protocol.name")
	} else if share.Protocol.Options == nil {
		return api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("protocol.options")
	} else if share.Protocol.Options == nil {
		return api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("protocol.options")
	} else if err := s.um.UserExists(ctx, share.ShareWith); err != nil {
		return api.NewAPIError(api.APIErrorInvalidParameter).WithMessage(fmt.Sprintf("shareWith does not exists: %s", err.Error()))
	} else {
		return nil
	}

}
