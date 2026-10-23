package funcs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/fujiwara/tfstate-lookup/tfstate"
)

type awsSecretsManager struct{ c *secretsmanager.Client }

func newAWSSecretsManager(ctx context.Context) (AWSSecretsManager, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &awsSecretsManager{c: secretsmanager.NewFromConfig(cfg)}, nil
}

func (a *awsSecretsManager) GetSecretString(ctx context.Context, id string) (string, error) {
	out, err := a.c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(id)})
	if err != nil {
		return "", err
	}
	if out.SecretString != nil {
		return *out.SecretString, nil
	}
	return string(out.SecretBinary), nil
}

type gcpSecretManager struct{ c *secretmanager.Client }

func newGCPSecretManager(ctx context.Context) (GCPSecretManager, error) {
	c, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	return &gcpSecretManager{c: c}, nil
}

func (g *gcpSecretManager) AccessSecretVersion(ctx context.Context, name string) (string, error) {
	resp, err := g.c.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: name})
	if err != nil {
		return "", err
	}
	return string(resp.GetPayload().GetData()), nil
}

// tfstateReader reads each state once and serves lookups from it.
type tfstateReader struct {
	states map[string]*tfstate.TFState
	mu     sync.Mutex
}

func newTFStateReader() *tfstateReader {
	return &tfstateReader{states: map[string]*tfstate.TFState{}}
}

func (t *tfstateReader) Lookup(ctx context.Context, url, address string) ([]byte, error) {
	t.mu.Lock()
	st, ok := t.states[url]
	if !ok {
		var err error
		st, err = tfstate.ReadURL(ctx, url)
		if err != nil {
			t.mu.Unlock()
			return nil, err
		}
		t.states[url] = st
	}
	t.mu.Unlock()

	obj, err := st.Lookup(address)
	if err != nil {
		return nil, fmt.Errorf("lookup %q in %s: %w", address, url, err)
	}
	if obj == nil || obj.Value == nil {
		return nil, errors.New("tfstate: " + address + " not found in " + url)
	}
	return json.Marshal(obj.Value)
}
