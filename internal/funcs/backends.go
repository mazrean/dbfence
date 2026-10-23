package funcs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
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

func (t *tfstateReader) Lookup(ctx context.Context, loc, address string) ([]byte, error) {
	if _, err := url.Parse(loc); err != nil {
		// The parse error quotes the URL, which may hold a password.
		return nil, errors.New("tfstate: the state URL cannot be parsed; check it for unescaped % or control characters")
	}
	t.mu.Lock()
	st, ok := t.states[loc]
	if !ok {
		var err error
		st, err = tfstate.ReadURL(ctx, loc)
		if err != nil {
			t.mu.Unlock()
			// Not wrapped: the cause repeats the URL, which may carry
			// credentials or a signed query string.
			_, r := redactURL(loc)
			return nil, errors.New(r.Replace(err.Error()))
		}
		t.states[loc] = st
	}
	t.mu.Unlock()

	shown, _ := redactURL(loc)
	obj, err := st.Lookup(address)
	if err != nil {
		return nil, fmt.Errorf("lookup %q in %s: %w", address, shown, err)
	}
	if obj == nil || obj.Value == nil {
		return nil, errors.New("tfstate: " + address + " not found in " + shown)
	}
	return json.Marshal(obj.Value)
}

// redactURL returns loc without its userinfo password, query string and
// fragment, and a replacer that masks those parts in a message. Local
// paths are returned as is.
func redactURL(loc string) (string, *strings.Replacer) {
	u, err := url.Parse(loc)
	if err != nil || u.Scheme == "" {
		return loc, strings.NewReplacer()
	}
	clean := *u
	clean.RawQuery, clean.ForceQuery, clean.Fragment, clean.RawFragment = "", false, "", ""
	safe := clean.Redacted()

	// Every form in which the URL may be printed: as given, re-encoded
	// by url.String, as masked by net/http (user:***@) and by
	// url.Redacted. The bare query, fragment and password are a backstop.
	olds := []string{loc, u.String()}
	olds = append(olds, strings.Replace(u.Redacted(), ":xxxxx@", ":***@", 1), u.Redacted())
	// Each part is also replaced in its Go-quoted form, because errors
	// such as net/http's print the URL with %q.
	var pairs []string
	add := func(old, repl string) {
		pairs = append(pairs, old, repl)
		if q := goQuoted(old); q != old {
			pairs = append(pairs, q, goQuoted(repl))
		}
	}
	for _, o := range olds {
		add(o, safe)
	}
	if u.RawQuery != "" {
		add(u.RawQuery, "REDACTED")
	}
	if u.Fragment != "" {
		add(u.EscapedFragment(), "REDACTED")
	}
	if pw, ok := u.User.Password(); ok && pw != "" {
		add(pw, "xxxxx")
	}
	return safe, strings.NewReplacer(pairs...)
}

// goQuoted returns s as it appears inside a %q-formatted string.
func goQuoted(s string) string {
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}
