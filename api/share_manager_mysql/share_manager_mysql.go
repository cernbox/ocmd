package share_manager_mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cernbox/ocmd/api"
	_ "github.com/go-sql-driver/mysql"
	"go.uber.org/zap"
)

type shareManager struct {
	host   string
	table  string
	logger *zap.Logger
	opt    *api.MySQLOptions
}

func New(host string, opt *api.MySQLOptions) api.ShareManager {

	return &shareManager{
		host:   host,
		logger: opt.Logger,
		table:  opt.Table,
		opt:    opt,
	}
}

func (sm *shareManager) GetInternalShare(ctx context.Context, shareID string) (*api.Share, error) {

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", sm.opt.Username, sm.opt.Password, sm.opt.Hostname, sm.opt.Port, sm.opt.DB))
	if err != nil {
		sm.logger.Error("CANNOT CONNECT TO MYSQL SERVER", zap.String("HOSTNAME", sm.opt.Hostname), zap.Int("PORT", sm.opt.Port), zap.String("DB", sm.opt.DB))
		return nil, nil
	}
	defer db.Close()

	var (
		file_target   string
		uid_owner     string
		uid_initiator string
		share_with    string
		token         string
	)
	query := fmt.Sprintf("SELECT file_target, uid_owner, uid_initiator, share_with, token FROM %s WHERE id=?", sm.table)
	err = db.QueryRow(query, shareID).Scan(&file_target, &uid_owner, &uid_initiator, &share_with, &token)
	if err != nil {
		if err == sql.ErrNoRows {
			sm.logger.Error("INVALID SHARE ID")
		} else {
			sm.logger.Error("CANNOT QUERY STATEMENT")
		}
		return nil, err
	}

	path := strings.Split(file_target, "/")

	ocShare := &api.Share{
		ShareWith:         share_with,
		Name:              path[len(path)-1],
		Description:       "",
		ProviderID:        shareID,
		Owner:             uid_owner + "@" + sm.host,
		Sender:            uid_initiator + "@" + sm.host,
		OwnerDisplayName:  uid_owner,     //LDAP CALL
		SenderDisplayName: uid_initiator, //LDAP CALL
		ShareType:         "user",
		ResourceType:      "file",
		Protocol: &api.ProtocolInfo{
			Name: "webdav",
			Options: &api.ProtocolOptions{
				SharedSecret: token,
				Permissions:  "{http://open-cloud-mesh.org/ns}share-permissions",
			},
		},
	}

	return ocShare, nil
}

func (sm *shareManager) GetShares(ctx context.Context, sharedWith string) ([]*api.Share, error) {

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", sm.opt.Username, sm.opt.Password, sm.opt.Hostname, sm.opt.Port, sm.opt.DB))
	if err != nil {
		sm.logger.Error("CANNOT CONNECT TO MYSQL SERVER", zap.String("HOSTNAME", sm.opt.Hostname), zap.Int("PORT", sm.opt.Port), zap.String("DB", sm.opt.DB))
		return nil, nil
	}
	defer db.Close()

	// query := fmt.Sprintf("SELECT file_target, stime FROM %s WHERE share_type=5 and share_with=?", sm.table)

	query := fmt.Sprintf("SELECT id, file_target, uid_owner, uid_initiator, token, stime FROM %s WHERE share_with=? and share_type=5", sm.table)
	rows, err := db.Query(query, sharedWith)

	if err != nil {
		sm.logger.Error("CANNOT QUERY STATEMENT")
		return nil, err
	}
	defer rows.Close()

	var (
		id            int
		file_target   string
		uid_owner     string
		uid_initiator string
		token         string
		stime         int64
	)
	ocShares := []*api.Share{}

	for rows.Next() {
		err = rows.Scan(&id, &file_target, &uid_owner, &uid_initiator, &token, &stime)

		if err != nil {
			sm.logger.Error("ERROR GETTING ROW")
			return nil, err
		}

		path := strings.Split(file_target, "/")
		createdAt := time.Unix(stime, 0)
		idStr := strconv.Itoa(id)

		ocShare := &api.Share{
			ShareWith:         sharedWith,
			Name:              path[len(path)-1],
			Description:       "",
			ID:                idStr,
			CreatedAt:         createdAt.Format("2006-01-02T15:04:05Z"),
			Owner:             uid_owner,
			Sender:            uid_initiator,
			OwnerDisplayName:  uid_owner,
			SenderDisplayName: uid_initiator,
			ShareType:         "user",
			ResourceType:      "file",
			Protocol: &api.ProtocolInfo{
				Name: "webdav",
				Options: &api.ProtocolOptions{
					SharedSecret: token,
					Permissions:  "{http://open-cloud-mesh.org/ns}share-permissions",
				},
			},
		}
		ocShares = append(ocShares, ocShare)
	}

	return ocShares, nil
}

func (sm *shareManager) GetExternalShare(ctx context.Context, sharedWith, shareID string) (*api.Share, error) {

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", sm.opt.Username, sm.opt.Password, sm.opt.Hostname, sm.opt.Port, sm.opt.DB))
	if err != nil {
		sm.logger.Error("CANNOT CONNECT TO MYSQL SERVER", zap.String("HOSTNAME", sm.opt.Hostname), zap.Int("PORT", sm.opt.Port), zap.String("DB", sm.opt.DB))
		return nil, nil
	}
	defer db.Close()

	var (
		file_target   string
		uid_owner     string
		uid_initiator string
		token         string
		stime         int64
	)
	query := fmt.Sprintf("SELECT file_target, uid_owner, uid_initiator, token, stime FROM %s WHERE id=? and share_with=? and share_type=5", sm.table)
	err = db.QueryRow(query, shareID, sharedWith).Scan(&file_target, &uid_owner, &uid_initiator, &token, &stime)
	if err != nil {
		if err == sql.ErrNoRows {
			sm.logger.Error("INVALID SHARE ID")
		} else {
			sm.logger.Error("CANNOT QUERY STATEMENT")
		}
		return nil, err
	}

	path := strings.Split(file_target, "/")
	createdAt := time.Unix(stime, 0)

	ocShare := &api.Share{
		ShareWith:         sharedWith,
		Name:              path[len(path)-1],
		Description:       "",
		ID:                shareID,
		CreatedAt:         createdAt.Format("2006-01-02T15:04:05Z"),
		Owner:             uid_owner,
		Sender:            uid_initiator,
		OwnerDisplayName:  uid_owner,
		SenderDisplayName: uid_initiator,
		ShareType:         "user",
		ResourceType:      "file",
		Protocol: &api.ProtocolInfo{
			Name: "webdav",
			Options: &api.ProtocolOptions{
				SharedSecret: token,
				Permissions:  "{http://open-cloud-mesh.org/ns}share-permissions",
			},
		},
	}

	return ocShare, nil
}

func (sm *shareManager) NewShare(ctx context.Context, share *api.Share, domain, shareWith string) (*api.Share, error) {
	err := sm.validateShare(ctx, share)
	if err != nil {
		return nil, err
	}

	createdAt := time.Now()
	providerID, _ := strconv.Atoi(share.ProviderID) //TODO error

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", sm.opt.Username, sm.opt.Password, sm.opt.Hostname, sm.opt.Port, sm.opt.DB))
	if err != nil {
		sm.logger.Error("CANNOT CONNECT TO MYSQL SERVER", zap.String("HOSTNAME", sm.opt.Hostname), zap.Int("PORT", sm.opt.Port), zap.String("DB", sm.opt.DB))
		return nil, nil
	}
	defer db.Close()

	itemType := "folder"

	query := fmt.Sprintf("INSERT INTO oc_share(share_type, share_with, uid_owner, uid_initiator, item_type, file_target, stime, token, ocm_id, ocm_domain, ocm_owner_name, ocm_sender_name) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")

	stmt, err := db.Prepare(query)
	if err != nil {
		sm.logger.Error("Error preparing the Query", zap.Error(err))
		return nil, err
	}

	res, err := stmt.Exec(5, shareWith, share.Owner, share.Sender, itemType, "/"+share.Name, createdAt.Unix(), share.Protocol.Options.SharedSecret, providerID, domain, share.OwnerDisplayName, share.SenderDisplayName)
	if err != nil {
		sm.logger.Error("Error executing the Query", zap.Error(err))
		return nil, err
	}

	returnedID, err := res.LastInsertId()
	if err != nil {
		sm.logger.Error("Error getting last ID", zap.Error(err))
		return nil, err
	}

	share.ID = strconv.FormatInt(returnedID, 10)
	share.CreatedAt = createdAt.Format("2006-01-02T15:04:05Z")

	return share, nil
}

func (sm *shareManager) validateShare(ctx context.Context, share *api.Share) error {
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
	} else if share.Protocol.Options.SharedSecret == "" {
		return api.NewAPIError(api.APIErrorInvalidParameter).WithMessage("sharedSecret")
	} else {
		return nil
	}

}
