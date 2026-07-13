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
