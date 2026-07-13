package azure

import (
	"errors"
	"net/url"

	az "github.com/Azure/azure-sdk-for-go/storage"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/graymeta/stow"
)

// ConfigAccount, ConfigKey, and ConfigSASToken are the supported
// configuration items for Azure blob storage. Either ConfigKey or
// ConfigSASToken must be present; ConfigSASToken is an alternative to
// ConfigKey, not additive.
const (
	ConfigAccount  = "account"
	ConfigKey      = "key"
	ConfigEnvName  = "envname"
	ConfigSASToken = "sastoken"
)

// Kind is the kind of Location this package provides.
const Kind = "azure"

func hasAuth(config stow.Config) bool {
	key, ok := config.Config(ConfigKey)
	if ok && key != "" {
		return true
	}
	sasToken, ok := config.Config(ConfigSASToken)
	return ok && sasToken != ""
}

func init() {
	validatefn := func(config stow.Config) error {
		_, ok := config.Config(ConfigAccount)
		if !ok {
			return errors.New("missing account id")
		}
		if !hasAuth(config) {
			return errors.New("missing auth key or sas token")
		}
		return nil
	}
	makefn := func(config stow.Config) (stow.Location, error) {
		_, ok := config.Config(ConfigAccount)
		if !ok {
			return nil, errors.New("missing account id")
		}
		if !hasAuth(config) {
			return nil, errors.New("missing auth key or sas token")
		}
		l := &location{
			config: config,
		}
		var err error
		l.client, err = newBlobStorageClient(l.config)
		if err != nil {
			return nil, err
		}
		// test the connection
		_, _, err = l.Containers("", stow.CursorStart, 1)
		if err != nil {
			return nil, err
		}
		return l, nil
	}
	kindfn := func(u *url.URL) bool {
		return u.Scheme == Kind
	}
	stow.Register(Kind, makefn, kindfn, validatefn)
}

func newBlobStorageClient(cfg stow.Config) (*az.BlobStorageClient, error) {
	acc, ok := cfg.Config(ConfigAccount)
	if !ok {
		return nil, errors.New("missing account id")
	}

	env := azure.PublicCloud
	envName, ok := cfg.Config(ConfigEnvName)
	if ok && envName != "" {
		var err error
		env, err = azure.EnvironmentFromName(envName)
		if err != nil {
			return nil, err
		}
	}

	if sasToken, ok := cfg.Config(ConfigSASToken); ok && sasToken != "" {
		endpoint := "https://" + acc + ".blob." + env.StorageEndpointSuffix
		sasClient, err := az.NewAccountSASClientFromEndpointToken(endpoint, sasToken)
		if err != nil {
			return nil, errors.New("bad credentials")
		}
		client := sasClient.GetBlobService()
		return &client, nil
	}

	key, ok := cfg.Config(ConfigKey)
	if !ok {
		return nil, errors.New("missing auth key")
	}

	var basicClient az.Client
	var err error
	if envName != "" {
		basicClient, err = az.NewBasicClientOnSovereignCloud(acc, key, env)
	} else {
		basicClient, err = az.NewBasicClient(acc, key)
	}

	if err != nil {
		return nil, errors.New("bad credentials")
	}
	client := basicClient.GetBlobService()
	return &client, err
}
