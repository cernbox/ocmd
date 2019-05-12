package provider_manager_mysql

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/cernbox/ocmd/api"
	_ "github.com/go-sql-driver/mysql"
	"go.uber.org/zap"
)

type providerAuthorizer struct {
	db     *sql.DB
	logger *zap.Logger
}

func New(opt *api.MySQLOptions) api.ProviderAuthorizer {

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", opt.Username, opt.Password, opt.Hostname, opt.Port, opt.DB))
	if err != nil {
		opt.Logger.Error("CANNOT CONNECT TO MYSQL SERVER", zap.String("HOSTNAME", opt.Hostname), zap.Int("PORT", opt.Port), zap.String("DB", opt.DB))
		return nil
	}

	return &providerAuthorizer{
		db:     db,
		logger: opt.Logger,
	}
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

func (pa *providerAuthorizer) getByDomain(ctx context.Context, domain string) (*api.ProviderInfo, error) {

	var apiVersion string
	var apiEndpoint string
	var webdavEndpoint string
	query := "SELECT api_version, api_endpoint, webdav_endpoint  FROM ocm_providers WHERE domain=?"
	err := pa.db.QueryRow(query, domain).Scan(&apiVersion, &apiEndpoint, &webdavEndpoint)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, api.NewAPIError(api.APIErrorUntrustedService)
		}
		pa.logger.Error("CANNOT QUERY STATEMENT")
		return nil, err
	}
	provider := &api.ProviderInfo{
		Domain:         domain,
		APIVersion:     apiVersion,
		APIEndPoint:    apiEndpoint,
		WebdavEndPoint: webdavEndpoint,
	}
	return provider, nil
}

func (pa *providerAuthorizer) AddProvider(ctx context.Context, p *api.ProviderInfo) error {

	query := "INSERT INTO ocm_providers(domain, api_version, api_endpoint, webdav_endpoint) values(?, ?, ?, ?)"
	stmt, err := pa.db.Prepare(query)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(p.Domain, p.APIVersion, p.APIEndPoint, p.WebdavEndPoint)
	if err != nil {
		return err
	}
	return nil
}
