package user_manager_memory

import (
	"context"
	"strings"

	"github.com/cernbox/ocmd/api"
)

type userManager struct {
	internalUsers []string
}

func New(usersString string) api.UserManager {
	users := strings.Split(usersString, ",")
	um := &userManager{internalUsers: users}
	return um
}

func (um *userManager) UserExists(ctx context.Context, username string) error {
	for _, u := range um.internalUsers {
		if u == username {
			return nil
		}
	}
	return api.NewAPIError(api.APIErrorNotFound)
}
