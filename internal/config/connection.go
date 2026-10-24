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
	Port           *int    `hcl:"port"`
	ConnectTimeout *int    `hcl:"connect_timeout"`
	Password       *string `hcl:"password"`
	Database       *string `hcl:"database"`
	TLS            *string `hcl:"tls"`
	Engine         string  `hcl:"engine"`
	Host           string  `hcl:"host"`
	User           string  `hcl:"user"`
}

// Connection defaults.
const (
	defaultTLS            = model.TLSPrefer
	defaultConnectTimeout = 10 * time.Second
	defaultPostgresPort   = 5432
	defaultMySQLPort      = 3306
)

var defaultPorts = map[model.Engine]int{model.EnginePostgres: defaultPostgresPort, model.EngineMySQL: defaultMySQLPort}

// decodeConnection decodes and checks the connection block b, and
// registers its password as a secret and its user and database as
// public names, which output shows by design.
func decodeConnection(b *hcl.Block, ctx *hcl.EvalContext) (model.Connection, hcl.Diagnostics) {
	var blk connectionBlock
	if diags := gohcl.DecodeBody(b.Body, ctx, &blk); diags.HasErrors() {
		return model.Connection{}, diags
	}
	conn := model.Connection{
		Engine:         model.Engine(blk.Engine),
		Host:           blk.Host,
		User:           blk.User,
		Password:       deref(blk.Password),
		Database:       deref(blk.Database),
		TLS:            model.TLSMode(deref(blk.TLS)),
		Port:           defaultPorts[model.Engine(blk.Engine)],
		ConnectTimeout: defaultConnectTimeout,
	}
	secret.Register(conn.Password)
	secret.RegisterPublic(conn.User)
	secret.RegisterPublic(conn.Database)

	attrs, _ := b.Body.JustAttributes()
	at := func(name, summary, detail string) hcl.Diagnostics {
		return hcl.Diagnostics{errAt(attrRange(attrs, name, b.DefRange), summary, detail)}
	}
	if conn.Engine != model.EngineMySQL && conn.Engine != model.EnginePostgres {
		return conn, at("engine", "Unsupported engine",
			fmt.Sprintf("engine must be %q or %q, got %q.", model.EngineMySQL, model.EnginePostgres, blk.Engine))
	}
	var diags hcl.Diagnostics
	// The drivers would silently fall back to defaults for empty values.
	empty := map[string]bool{"host": strings.TrimSpace(conn.Host) == "", "user": strings.TrimSpace(conn.User) == ""}
	if blk.Database != nil && conn.Engine == model.EnginePostgres {
		empty["database"] = strings.TrimSpace(conn.Database) == ""
	}
	for _, name := range []string{"host", "user", "database"} {
		if empty[name] {
			diags = append(diags, at(name, "Empty value",
				fmt.Sprintf("connection.%s must not be empty (an env() or secret lookup may have returned an empty value).", name))...)
		}
	}
	if conn.Engine == model.EnginePostgres && blk.Database == nil {
		conn.Database = "postgres"
	}
	if blk.Port != nil {
		if *blk.Port < 1 || *blk.Port > 65535 {
			diags = append(diags, at("port", "Invalid port", fmt.Sprintf("port must be between 1 and 65535, got %d.", *blk.Port))...)
		}
		conn.Port = *blk.Port
	}
	if blk.ConnectTimeout != nil {
		if *blk.ConnectTimeout < 1 {
			diags = append(diags, at("connect_timeout", "Invalid connect_timeout",
				fmt.Sprintf("connect_timeout is in seconds and must be at least 1, got %d.", *blk.ConnectTimeout))...)
		}
		conn.ConnectTimeout = time.Duration(*blk.ConnectTimeout) * time.Second
	}
	switch {
	case blk.TLS == nil:
		conn.TLS = defaultTLS
	case !slices.Contains(model.TLSModes, conn.TLS):
		diags = append(diags, at("tls", "Invalid tls",
			fmt.Sprintf("tls must be one of %q, got %q.", model.TLSModes, conn.TLS))...)
	}
	return conn, diags
}
