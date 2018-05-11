package internal_share_manager_python

import (
	"context"
	"fmt"
	"github.com/cernbox/ocmd/api"
)

type internalShareManager struct {
	pythonScript string // location of the python script to invoke
}

func New(pythonScript string) api.InternalShareManager {
	return &internalShareManager{pythonScript: pythonScript}

}

func (ism *internalShareManager) NewInternalShare(ctx context.Context, share *api.Share) (*api.Share, error) {
	return nil, fmt.Errorf("TODO")
}

func (ism *internalShareManager) CommitInternalShare(ctx context.Context, providerID, consumerID string) (*api.Share, error) {
	return nil, fmt.Errorf("TODO")
}
