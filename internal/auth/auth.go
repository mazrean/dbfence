// Package auth provides the password that dbfence sends when it opens a
// connection: the configured one, or an IAM token of a cloud provider.
package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/credentials"
	"github.com/aws/aws-sdk-go-v2/aws"
	rdsauth "github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/mazrean/dbfence/internal/funcs"
	"github.com/mazrean/dbfence/internal/model"
)

// Source returns the password of a new connection. IAM tokens expire,
// so drivers call it for every connection they open.
type Source func(ctx context.Context) (string, error)

// gcpIAMScope is the OAuth scope of Cloud SQL IAM database logins.
const gcpIAMScope = "https://www.googleapis.com/auth/sqlservice.login"

// New returns the Source of conn.
func New(conn model.Connection) Source {
	switch conn.Auth {
	case model.AuthAWSIAM:
		return awsIAM(conn, funcs.LoadAWSConfig)
	case model.AuthGCPIAM:
		return gcpIAM(func() (auth.TokenProvider, error) {
			return credentials.DetectDefault(&credentials.DetectOptions{Scopes: []string{gcpIAMScope}, Logger: funcs.SDKLogger()})
		})
	case model.AuthPassword:
	}
	return Static(conn.Password)
}

// Static returns a Source of password.
func Static(password string) Source {
	return func(context.Context) (string, error) { return password, nil }
}

// awsIAM returns a Source of Amazon RDS IAM authentication tokens for
// conn, with credentials from the AWS configuration that load returns.
func awsIAM(conn model.Connection, load func(context.Context) (aws.Config, error)) Source {
	endpoint := net.JoinHostPort(conn.Host, strconv.Itoa(conn.Port))
	cfg := once(load)
	return func(ctx context.Context) (string, error) {
		c, err := cfg(ctx)
		if err != nil {
			return "", fmt.Errorf("aws_iam: load AWS configuration: %w", err)
		}
		region := conn.AWSRegion
		if region == "" {
			region = c.Region
		}
		if region == "" {
			return "", errors.New("aws_iam: no AWS region: set aws_iam.region or AWS_REGION")
		}
		token, err := rdsauth.BuildAuthToken(ctx, endpoint, region, conn.User, c.Credentials)
		if err != nil {
			return "", fmt.Errorf("aws_iam: build authentication token: %w", err)
		}
		return token, nil
	}
}

// gcpIAM returns a Source of Google Cloud access tokens from the
// credentials that detect finds.
func gcpIAM(detect func() (auth.TokenProvider, error)) Source {
	provider := once(func(context.Context) (auth.TokenProvider, error) { return detect() })
	return func(ctx context.Context) (string, error) {
		p, err := provider(ctx)
		if err != nil {
			return "", fmt.Errorf("gcp_iam: find Google Cloud credentials: %w", err)
		}
		token, err := p.Token(ctx)
		if err != nil {
			return "", fmt.Errorf("gcp_iam: get access token: %w", err)
		}
		return token.Value, nil
	}
}

// once returns f memoized after its first success. AWS and GCP
// credentials cache and refresh their tokens themselves, so they are
// created once.
func once[T any](f func(context.Context) (T, error)) func(context.Context) (T, error) {
	var (
		mu   sync.Mutex
		done bool
		v    T
	)
	return func(ctx context.Context) (T, error) {
		mu.Lock()
		defer mu.Unlock()
		if done {
			return v, nil
		}
		r, err := f(ctx)
		if err != nil {
			return r, err
		}
		v, done = r, true
		return v, nil
	}
}
