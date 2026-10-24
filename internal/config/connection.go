package config

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/secret"
)

type connectionBlock struct {
	AWSIAM         *awsIAMBlock `hcl:"aws_iam,block"`
	GCPIAM         *gcpIAMBlock `hcl:"gcp_iam,block"`
	Port           *int         `hcl:"port"`
	ConnectTimeout *int         `hcl:"connect_timeout"`
	Host           *string      `hcl:"host"`
	Socket         *string      `hcl:"socket"`
	Password       *string      `hcl:"password"`
	Database       *string      `hcl:"database"`
	TLS            *string      `hcl:"tls"`
	TLSCAFile      *string      `hcl:"tls_ca_file"`
	User           string       `hcl:"user"`
}

type awsIAMBlock struct {
	Region *string `hcl:"region"`
}

type gcpIAMBlock struct{}

// Connection defaults.
const (
	defaultConnectTimeout = 10 * time.Second
	defaultPostgresPort   = 5432
	defaultMySQLPort      = 3306
)

var defaultPorts = map[model.Engine]int{model.EnginePostgres: defaultPostgresPort, model.EngineMySQL: defaultMySQLPort}

// cleartextTLS are the TLS modes that may send a password unencrypted.
var cleartextTLS = []model.TLSMode{model.TLSDisable, model.TLSAllow, model.TLSPrefer}

// decodeConnection decodes and checks the connection block b, whose label
// is the engine, and registers its password as a secret and its user and
// database as public names, which output shows by design.
func decodeConnection(b *hcl.Block, ctx *hcl.EvalContext) (model.Connection, hcl.Diagnostics) {
	engine := model.Engine(b.Labels[0])
	if engine != model.EngineMySQL && engine != model.EnginePostgres {
		return model.Connection{}, hcl.Diagnostics{errAt(b.LabelRanges[0], "Unsupported engine",
			fmt.Sprintf("The connection label must be %q or %q, got %q.", model.EngineMySQL, model.EnginePostgres, engine))}
	}
	var blk connectionBlock
	if diags := gohcl.DecodeBody(b.Body, ctx, &blk); diags.HasErrors() {
		return model.Connection{}, diags
	}
	conn := model.Connection{
		Engine:         engine,
		Auth:           model.AuthPassword,
		Host:           deref(blk.Host),
		Socket:         deref(blk.Socket),
		User:           blk.User,
		Password:       deref(blk.Password),
		Database:       deref(blk.Database),
		TLSCAFile:      deref(blk.TLSCAFile),
		Port:           defaultPorts[engine],
		ConnectTimeout: defaultConnectTimeout,
	}
	secret.Register(conn.Password)
	secret.RegisterPublic(conn.User)
	secret.RegisterPublic(conn.Database)

	// JustAttributes also reports the nested blocks; only the attribute
	// ranges are needed here.
	attrs, _ := b.Body.JustAttributes()
	ranges := map[string]hcl.Range{}
	for name, a := range attrs {
		ranges[name] = a.Range
	}
	nested, _, _ := b.Body.PartialContent(&hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "aws_iam"}, {Type: "gcp_iam"}}})
	for _, nb := range nested.Blocks {
		ranges[nb.Type] = nb.DefRange
	}
	var diags hcl.Diagnostics
	fail := func(name, summary, detail string) {
		rng, ok := ranges[name]
		if !ok {
			rng = b.DefRange
		}
		diags = append(diags, errAt(rng, summary, detail))
	}

	// Authentication.
	var methods []string
	for _, m := range []string{"password", "aws_iam", "gcp_iam"} {
		if _, ok := ranges[m]; ok {
			methods = append(methods, m)
		}
	}
	if len(methods) > 1 {
		fail(methods[1], "Conflicting authentication",
			fmt.Sprintf("%s and %s cannot both be set: use password, aws_iam or gcp_iam.", methods[0], methods[1]))
	}
	switch {
	case blk.AWSIAM != nil:
		conn.Auth, conn.AWSRegion = model.AuthAWSIAM, deref(blk.AWSIAM.Region)
	case blk.GCPIAM != nil:
		conn.Auth = model.AuthGCPIAM
	}

	// Where to connect.
	switch {
	case blk.Socket != nil && engine != model.EngineMySQL:
		fail("socket", "Unsupported attribute", `"socket" is only supported for mysql; on postgres, set host to the socket directory.`)
	case blk.Socket != nil:
		for _, name := range []string{"host", "port"} {
			if _, ok := ranges[name]; ok {
				fail(name, "Conflicting attributes", fmt.Sprintf("%s cannot be set together with socket.", name))
			}
		}
		if strings.TrimSpace(conn.Socket) == "" {
			fail("socket", "Empty value", "connection.socket must not be empty (an env() or secret lookup may have returned an empty value).")
		}
		if conn.Auth == model.AuthAWSIAM {
			fail("aws_iam", "Unsupported authentication", "aws_iam needs host and port, which the token is signed for; it cannot be used with socket.")
		}
	case blk.Host == nil:
		detail := "connection.host is required."
		if engine == model.EngineMySQL {
			detail = "connection.host or connection.socket is required."
		}
		fail("host", "Missing host", detail)
	}
	empty := map[string]bool{
		"host": blk.Host != nil && strings.TrimSpace(conn.Host) == "",
		"user": strings.TrimSpace(conn.User) == "",
		// Without a database PostgreSQL connects to the one named
		// like the user.
		"database":    engine == model.EnginePostgres && blk.Database != nil && strings.TrimSpace(conn.Database) == "",
		"tls_ca_file": blk.TLSCAFile != nil && strings.TrimSpace(conn.TLSCAFile) == "",
	}
	for _, name := range []string{"host", "user", "database", "tls_ca_file"} {
		if empty[name] {
			fail(name, "Empty value",
				fmt.Sprintf("connection.%s must not be empty (an env() or secret lookup may have returned an empty value).", name))
		}
	}
	if engine == model.EnginePostgres && blk.Database == nil {
		conn.Database = "postgres"
	}
	if blk.Port != nil {
		if *blk.Port < 1 || *blk.Port > 65535 {
			fail("port", "Invalid port", fmt.Sprintf("port must be between 1 and 65535, got %d.", *blk.Port))
		}
		conn.Port = *blk.Port
	}
	if blk.ConnectTimeout != nil {
		if *blk.ConnectTimeout < 1 {
			fail("connect_timeout", "Invalid connect_timeout",
				fmt.Sprintf("connect_timeout is in seconds and must be at least 1, got %d.", *blk.ConnectTimeout))
		}
		conn.ConnectTimeout = time.Duration(*blk.ConnectTimeout) * time.Second
	}

	// TLS.
	conn.TLS = defaultTLS(conn)
	if blk.TLS != nil {
		conn.TLS = model.TLSMode(*blk.TLS)
		if !slices.Contains(model.TLSModes[engine], conn.TLS) {
			fail("tls", "Invalid tls", fmt.Sprintf("tls must be one of %q for %s, got %q.", model.TLSModes[engine], engine, conn.TLS))
		}
	}
	if conn.Auth != model.AuthPassword && conn.Socket == "" && slices.Contains(cleartextTLS, conn.TLS) {
		fail("tls", "Insecure tls", fmt.Sprintf("IAM tokens are sent as a cleartext password, so %s needs tls = \"require\" or a verifying mode, got %q.", conn.Auth, conn.TLS))
	}
	if conn.Socket != "" && conn.TLS == model.TLSVerifyFull {
		fail("tls", "Invalid tls", `tls = "verify-full" checks a host name, which a socket connection does not have.`)
	}
	if blk.TLSCAFile != nil && conn.TLS != model.TLSVerifyCA && conn.TLS != model.TLSVerifyFull {
		fail("tls_ca_file", "Unused tls_ca_file", fmt.Sprintf("tls_ca_file is only used by a verifying tls mode, got tls = %q.", conn.TLS))
	}
	return conn, diags
}

// defaultTLS is the TLS mode of conn when the configuration sets none:
// IAM tokens must not be sent unencrypted, and a socket is local.
func defaultTLS(conn model.Connection) model.TLSMode {
	switch {
	case conn.Socket != "":
		return model.TLSDisable
	case conn.Auth != model.AuthPassword:
		return model.TLSRequire
	default:
		return model.TLSPrefer
	}
}
