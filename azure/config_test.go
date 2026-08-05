package azure

import (
	"testing"

	"github.com/cheekybits/is"
	"github.com/graymeta/stow"
)

func TestNewBlobStorageClientSASToken(t *testing.T) {
	is := is.New(t)

	cfg := stow.ConfigMap{
		ConfigAccount:  "testaccount",
		ConfigSASToken: "sv=2020-08-04&ss=b&srt=sco&sp=rwdlac&se=2099-01-01T00:00:00Z&sig=abc123",
	}
	client, err := newBlobStorageClient(cfg)
	is.NoErr(err)
	is.NotNil(client)
}

func TestNewBlobStorageClientRejectsNonHTTPSSASProtocol(t *testing.T) {
	is := is.New(t)

	// spr=https,http would make the Azure SDK send requests over plaintext HTTP
	// (useHTTPS = spr == "https"), overriding the https:// endpoint. Reject it.
	cfg := stow.ConfigMap{
		ConfigAccount:  "testaccount",
		ConfigSASToken: "sv=2020-08-04&ss=b&srt=sco&sp=rwdlac&spr=https,http&se=2099-01-01T00:00:00Z&sig=abc123",
	}
	client, err := newBlobStorageClient(cfg)
	is.Err(err)
	is.Nil(client)
}

func TestNewBlobStorageClientAcceptsHTTPSSASProtocol(t *testing.T) {
	is := is.New(t)

	// An explicit spr=https is the secure case and must keep working.
	cfg := stow.ConfigMap{
		ConfigAccount:  "testaccount",
		ConfigSASToken: "sv=2020-08-04&ss=b&srt=sco&sp=rwdlac&spr=https&se=2099-01-01T00:00:00Z&sig=abc123",
	}
	client, err := newBlobStorageClient(cfg)
	is.NoErr(err)
	is.NotNil(client)
}

func TestValidateAcceptsAccountAndSASTokenWithoutKey(t *testing.T) {
	is := is.New(t)

	cfg := stow.ConfigMap{
		ConfigAccount:  "testaccount",
		ConfigSASToken: "sv=2020-08-04&ss=b&srt=sco&sp=rwdlac&se=2099-01-01T00:00:00Z&sig=abc123",
	}
	is.True(hasAuth(cfg))
}

func TestValidateRejectsAccountOnly(t *testing.T) {
	is := is.New(t)

	cfg := stow.ConfigMap{
		ConfigAccount: "testaccount",
	}
	is.False(hasAuth(cfg))
}
