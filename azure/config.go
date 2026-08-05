package azure

import (
	"errors"
	"fmt"
	"net/url"

	az "github.com/Azure/azure-sdk-for-go/storage"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/graymeta/stow"
)

// ConfigAccount, ConfigKey, and ConfigSASToken are the supported
// configuration items for Azure blob storage. At least one of ConfigKey or
// ConfigSASToken must be present. ConfigSASToken is an alternative to
// ConfigKey, not additive; if both are supplied, ConfigSASToken takes
// precedence (see newBlobStorageClient).
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
	return usingSASToken(config)
}

// usingSASToken reports whether the config authenticates with a SAS token
// rather than a shared account key. SAS tokens minted for Azure Workload
// (federated) Identity are user-delegation SAS: they are scoped to a single
// container and cannot perform account-level operations such as listing
// containers, so callers must avoid account-level actions on this path.
func usingSASToken(config stow.Config) bool {
	sasToken, ok := config.Config(ConfigSASToken)
	return ok && sasToken != ""
}

// requireHTTPSSASProtocol rejects a SAS token whose signed protocol (spr) would
// permit non-HTTPS transport. The Azure storage SDK derives the request scheme
// from spr: newSASClient sets useHTTPS = (spr == "https") for any non-empty spr,
// which overrides the endpoint scheme, so a token with spr=https,http makes the
// client send requests over plaintext HTTP even against an https:// endpoint. An
// empty spr is allowed — the SDK then infers the scheme from the (https)
// endpoint. Parsed exactly as the SDK does (url.ParseQuery + Get("spr")).
func requireHTTPSSASProtocol(sasToken string) error {
	values, err := url.ParseQuery(sasToken)
	if err != nil {
		return fmt.Errorf("bad credentials: invalid SAS token: %w", err)
	}
	if spr := values.Get("spr"); spr != "" && spr != "https" {
		return fmt.Errorf("bad credentials: SAS token allows non-HTTPS transport (spr=%q); only https is permitted", spr)
	}
	return nil
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
		// A user-delegation SAS token (Azure Workload Identity) is scoped to a
		// single container and cannot list containers at the account level, so
		// skip the account-level connection probe on the SAS path. Access is
		// validated when the caller operates on its specific container.
		if !usingSASToken(config) {
			// test the connection
			if _, _, err = l.Containers("", stow.CursorStart, 1); err != nil {
				return nil, err
			}
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

	// SAS token takes precedence over a shared account key: it is checked first,
	// so if both are set (they are alternatives, not additive) the SAS token
	// wins. See the ConfigSASToken doc.
	if sasToken, ok := cfg.Config(ConfigSASToken); ok && sasToken != "" {
		if err := requireHTTPSSASProtocol(sasToken); err != nil {
			return nil, err
		}
		endpoint := "https://" + acc + ".blob." + env.StorageEndpointSuffix
		sasClient, err := az.NewAccountSASClientFromEndpointToken(endpoint, sasToken)
		if err != nil {
			return nil, fmt.Errorf("bad credentials: %w", err)
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
		return nil, fmt.Errorf("bad credentials: %w", err)
	}
	client := basicClient.GetBlobService()
	return &client, err
}
