package share_manager_python

import (
	"context"
	"fmt"
	"github.com/cernbox/ocmd/api"
)

type shareManager struct {
	pythonScript string // location of the python script invoke
}

func New(pythonScript string) api.ShareManager {
	return &shareManager{pythonScript: pythonScript}

}

func (sm *shareManager) GetShare(ctx context.Context, id string) (*api.Share, error) {
	// TODO(labkode)
	return nil, fmt.Errorf("TODO")
}

func (sm *shareManager) GetShares(ctx context.Context) ([]*api.Share, error) {
	// TODO(labkode)
	return nil, fmt.Errorf("TODO")
}

func (sm *shareManager) NewShare(ctx context.Context, share *api.Share) (*api.Share, error) {
	// TODO(labkode)
	return nil, fmt.Errorf("TODO")
}
