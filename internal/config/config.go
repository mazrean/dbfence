// Package config loads dbfence HCL configuration into the desired model.
package config

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// Config is a loaded configuration.
type Config struct {
	Desired *model.Desired
	Engine  model.Engine
	DSN     string
}

var rootSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "connection"},
		{Type: "database", LabelNames: []string{"name"}},
		{Type: "role", LabelNames: []string{"name"}},
		{Type: "user", LabelNames: []string{"name"}},
		{Type: "schema", LabelNames: []string{"name"}},
		{Type: "grant"},
		{Type: "ignore"},
	},
}

type connectionBlock struct {
	Engine string `hcl:"engine"`
	DSN    string `hcl:"dsn"`
}

type databaseBlock struct {
	Name      *string `hcl:"name"`
	Owner     *string `hcl:"owner"`
	Encoding  *string `hcl:"encoding"`
	LcCollate *string `hcl:"lc_collate"`
	LcCtype   *string `hcl:"lc_ctype"`
	Charset   *string `hcl:"charset"`
	Collation *string `hcl:"collation"`
}

type roleBlock struct {
	Name            *string   `hcl:"name"`
	Host            *string   `hcl:"host"`
	Login           *bool     `hcl:"login"`
	Password        *string   `hcl:"password"`
	MemberOf        *[]string `hcl:"member_of"`
	Superuser       *bool     `hcl:"superuser"`
	CreateDB        *bool     `hcl:"createdb"`
	CreateRole      *bool     `hcl:"createrole"`
	Inherit         *bool     `hcl:"inherit"`
	Replication     *bool     `hcl:"replication"`
	BypassRLS       *bool     `hcl:"bypassrls"`
	ConnectionLimit *int      `hcl:"connection_limit"`
	AuthPlugin      *string   `hcl:"auth_plugin"`
}

type schemaBlock struct {
	Name     *string `hcl:"name"`
	Owner    *string `hcl:"owner"`
	Database string  `hcl:"database"`
}

type grantBlock struct {
	Schema          *string  `hcl:"schema"`
	WithGrantOption *bool    `hcl:"with_grant_option"`
	Role            string   `hcl:"role"`
	Database        string   `hcl:"database"`
	Privileges      []string `hcl:"privileges"`
}

type ignoreBlock struct {
	Roles     *[]string `hcl:"roles"`
	Databases *[]string `hcl:"databases"`
	Schemas   *[]string `hcl:"schemas"`
}

// Load parses path (a file or a directory of *.hcl files).
func Load(path string, fns map[string]function.Function) (*Config, error) {
	files, err := hclFiles(path)
	if err != nil {
		return nil, err
	}
	parser := hclparse.NewParser()
	var bodies []*hcl.File
	var diags hcl.Diagnostics
	for _, f := range files {
		file, d := parser.ParseHCLFile(f)
		diags = append(diags, d...)
		if file != nil {
			bodies = append(bodies, file)
		}
	}
	if diags.HasErrors() {
		return nil, diagError(parser, diags)
	}
	cfg, diags := decode(hcl.MergeFiles(bodies), fns)
	if diags.HasErrors() {
		return nil, diagError(parser, diags)
	}
	return cfg, nil
}

func hclFiles(path string) ([]string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return []string{path}, nil
	}
	files, err := filepath.Glob(filepath.Join(path, "*.hcl"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no *.hcl files in %s", path)
	}
	slices.Sort(files)
	return files, nil
}

func diagError(p *hclparse.Parser, diags hcl.Diagnostics) error {
	var sb strings.Builder
	w := hcl.NewDiagnosticTextWriter(&sb, p.Files(), 0, false)
	if err := w.WriteDiagnostics(diags); err != nil {
		return diags
	}
	return fmt.Errorf("invalid configuration:\n%s", strings.TrimRight(sb.String(), "\n"))
}

// resource is a labeled block awaiting full decode.
type resource struct {
	block *hcl.Block
	name  string
	host  string
}

func decode(body hcl.Body, fns map[string]function.Function) (*Config, hcl.Diagnostics) {
	content, diags := body.Content(rootSchema)
	if diags.HasErrors() {
		return nil, diags
	}
	base := &hcl.EvalContext{Functions: fns}

	var conn *connectionBlock
	byType := map[string][]*hcl.Block{}
	for _, b := range content.Blocks {
		if b.Type == "connection" {
			if conn != nil {
				diags = append(diags, errAt(b.DefRange, "Duplicate connection block", "Only one connection block is allowed."))
				continue
			}
			conn = &connectionBlock{}
			diags = append(diags, gohcl.DecodeBody(b.Body, base, conn)...)
			continue
		}
		byType[b.Type] = append(byType[b.Type], b)
	}
	if conn == nil {
		return nil, append(diags, &hcl.Diagnostic{Severity: hcl.DiagError, Summary: "Missing connection block", Detail: `A connection block with "engine" and "dsn" is required.`})
	}
	if diags.HasErrors() {
		return nil, diags
	}
	engine := model.Engine(conn.Engine)
	if engine != model.EngineMySQL && engine != model.EnginePostgres {
		return nil, append(diags, &hcl.Diagnostic{Severity: hcl.DiagError, Summary: "Unsupported engine", Detail: fmt.Sprintf("engine must be %q or %q, got %q.", model.EngineMySQL, model.EnginePostgres, conn.Engine)})
	}

	// Pass 1: resolve names so blocks can reference each other.
	vars := map[string]map[string]cty.Value{}
	resources := map[string][]resource{}
	for _, typ := range []string{"database", "role", "user", "schema"} {
		for _, b := range byType[typ] {
			r, d := resolveName(b, base, engine)
			diags = append(diags, d...)
			if d.HasErrors() {
				continue
			}
			refType := typ
			if typ == "user" {
				refType = "role"
			}
			if vars[refType] == nil {
				vars[refType] = map[string]cty.Value{}
			}
			if _, dup := vars[refType][b.Labels[0]]; dup {
				diags = append(diags, errAt(b.LabelRanges[0], "Duplicate label", fmt.Sprintf("%s %q is defined more than once (role and user share a namespace).", typ, b.Labels[0])))
				continue
			}
			vars[refType][b.Labels[0]] = refValue(typ, r, engine, b, refContext(base, vars))
			resources[typ] = append(resources[typ], r)
		}
	}
	if diags.HasErrors() {
		return nil, diags
	}
	ctx := refContext(base, vars)
	for _, typ := range []string{"database", "role", "schema"} {
		if _, ok := ctx.Variables[typ]; !ok {
			ctx.Variables[typ] = cty.EmptyObjectVal
		}
	}
	ctx.Variables["user"] = ctx.Variables["role"]

	// Pass 2: full decode.
	d := &model.Desired{Engine: engine}
	for _, r := range resources["database"] {
		var blk databaseBlock
		if diags = append(diags, gohcl.DecodeBody(r.block.Body, ctx, &blk)...); diags.HasErrors() {
			continue
		}
		diags = append(diags, checkEngineOnly(r.block, engine, map[string]bool{
			"owner": blk.Owner != nil, "encoding": blk.Encoding != nil, "lc_collate": blk.LcCollate != nil, "lc_ctype": blk.LcCtype != nil,
		}, map[string]bool{"charset": blk.Charset != nil, "collation": blk.Collation != nil})...)
		d.Databases = append(d.Databases, model.Database{
			Name: r.name, Owner: deref(blk.Owner), Encoding: deref(blk.Encoding), LcCollate: deref(blk.LcCollate),
			LcCtype: deref(blk.LcCtype), Charset: deref(blk.Charset), Collation: deref(blk.Collation),
		})
	}
	for _, typ := range []string{"role", "user"} {
		for _, r := range resources[typ] {
			role, dd := decodeRole(r, typ, ctx, engine)
			diags = append(diags, dd...)
			if !dd.HasErrors() {
				d.Roles = append(d.Roles, role)
			}
		}
	}
	for _, r := range resources["schema"] {
		if engine != model.EnginePostgres {
			diags = append(diags, errAt(r.block.DefRange, "Unsupported block", "schema blocks are only supported for postgres; use database blocks for MySQL."))
			continue
		}
		var blk schemaBlock
		if diags = append(diags, gohcl.DecodeBody(r.block.Body, ctx, &blk)...); diags.HasErrors() {
			continue
		}
		d.Schemas = append(d.Schemas, model.Schema{Database: blk.Database, Name: r.name, Owner: deref(blk.Owner)})
	}
	for _, b := range byType["grant"] {
		privs, dd := decodeGrant(b, ctx, engine)
		diags = append(diags, dd...)
		d.Privileges = append(d.Privileges, privs...)
	}
	for _, b := range byType["ignore"] {
		var blk ignoreBlock
		if diags = append(diags, gohcl.DecodeBody(b.Body, ctx, &blk)...); diags.HasErrors() {
			continue
		}
		d.Ignore.Roles = append(d.Ignore.Roles, derefSlice(blk.Roles)...)
		d.Ignore.Databases = append(d.Ignore.Databases, derefSlice(blk.Databases)...)
		d.Ignore.Schemas = append(d.Ignore.Schemas, derefSlice(blk.Schemas)...)
		for _, p := range slices.Concat(derefSlice(blk.Roles), derefSlice(blk.Databases), derefSlice(blk.Schemas)) {
			if _, err := regexp.Compile(p); err != nil {
				diags = append(diags, errAt(b.DefRange, "Invalid ignore pattern", err.Error()))
			}
		}
	}
	if diags.HasErrors() {
		return nil, diags
	}
	diags = append(diags, validate(d)...)
	if diags.HasErrors() {
		return nil, diags
	}
	return &Config{Engine: engine, DSN: conn.DSN, Desired: d}, diags
}

func resolveName(b *hcl.Block, ctx *hcl.EvalContext, engine model.Engine) (resource, hcl.Diagnostics) {
	r := resource{block: b, name: b.Labels[0]}
	attrs, diags := b.Body.JustAttributes()
	if diags.HasErrors() {
		return r, diags
	}
	if a, ok := attrs["name"]; ok {
		diags = append(diags, gohcl.DecodeExpression(a.Expr, ctx, &r.name)...)
	}
	if a, ok := attrs["host"]; ok {
		if b.Type != "role" && b.Type != "user" {
			return r, diags
		}
		if engine != model.EngineMySQL {
			return r, append(diags, errAt(a.Range, "Unsupported attribute", `"host" is only supported for mysql.`))
		}
		diags = append(diags, gohcl.DecodeExpression(a.Expr, ctx, &r.host)...)
	} else if engine == model.EngineMySQL && (b.Type == "role" || b.Type == "user") {
		r.host = "%"
	}
	if r.name == "" {
		diags = append(diags, errAt(b.DefRange, "Empty name", "Object names must not be empty."))
	}
	return r, diags
}

// refValue is the value exposed to expressions as <type>.<label>.
func refValue(typ string, r resource, engine model.Engine, b *hcl.Block, ctx *hcl.EvalContext) cty.Value {
	switch typ {
	case "role", "user":
		id := r.name
		if engine == model.EngineMySQL {
			id = model.RoleID{Name: r.name, Host: r.host}.String()
		}
		return cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal(r.name), "host": cty.StringVal(r.host), "id": cty.StringVal(id)})
	case "schema":
		// Schemas may only reference databases, which are resolved first.
		attrs, _ := b.Body.JustAttributes()
		db := cty.UnknownVal(cty.String)
		if a, ok := attrs["database"]; ok {
			if v, d := a.Expr.Value(ctx); !d.HasErrors() && v.Type() == cty.String {
				db = v
			}
		}
		return cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal(r.name), "database": db})
	default:
		return cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal(r.name)})
	}
}

// refContext exposes the references resolved so far.
func refContext(base *hcl.EvalContext, vars map[string]map[string]cty.Value) *hcl.EvalContext {
	ctx := base.NewChild()
	ctx.Variables = map[string]cty.Value{}
	for typ, m := range vars {
		ctx.Variables[typ] = cty.ObjectVal(m)
	}
	return ctx
}

func decodeRole(r resource, typ string, ctx *hcl.EvalContext, engine model.Engine) (model.Role, hcl.Diagnostics) {
	var blk roleBlock
	diags := gohcl.DecodeBody(r.block.Body, ctx, &blk)
	if diags.HasErrors() {
		return model.Role{}, diags
	}
	diags = append(diags, checkEngineOnly(r.block, engine, map[string]bool{
		"superuser": blk.Superuser != nil, "createdb": blk.CreateDB != nil, "createrole": blk.CreateRole != nil,
		"inherit": blk.Inherit != nil, "replication": blk.Replication != nil, "bypassrls": blk.BypassRLS != nil,
		"connection_limit": blk.ConnectionLimit != nil,
	}, map[string]bool{"auth_plugin": blk.AuthPlugin != nil})...)
	login := blk.Login
	if login == nil {
		// "user" logs in by default, "role" does not, like CREATE USER / CREATE ROLE.
		v := typ == "user"
		login = &v
	}
	role := model.Role{
		ID: model.RoleID{Name: r.name, Host: r.host}, Login: login, Password: blk.Password,
		Superuser: blk.Superuser, CreateDB: blk.CreateDB, CreateRole: blk.CreateRole, Inherit: blk.Inherit,
		Replication: blk.Replication, BypassRLS: blk.BypassRLS, ConnectionLimit: blk.ConnectionLimit,
		AuthPlugin: deref(blk.AuthPlugin),
	}
	if blk.MemberOf != nil {
		role.MemberOf = []model.RoleID{}
		for _, m := range *blk.MemberOf {
			role.MemberOf = append(role.MemberOf, ParseRoleID(m, engine))
		}
		model.SortRoleIDs(role.MemberOf)
	}
	return role, diags
}

// ParseRoleID parses "name" or, for MySQL, "name@host" (host defaults to %).
func ParseRoleID(s string, engine model.Engine) model.RoleID {
	if engine != model.EngineMySQL {
		return model.RoleID{Name: s}
	}
	if name, host, ok := strings.CutLast(s, "@"); ok {
		return model.RoleID{Name: name, Host: host}
	}
	return model.RoleID{Name: s, Host: "%"}
}

func decodeGrant(b *hcl.Block, ctx *hcl.EvalContext, engine model.Engine) ([]model.Privilege, hcl.Diagnostics) {
	var blk grantBlock
	diags := gohcl.DecodeBody(b.Body, ctx, &blk)
	if diags.HasErrors() {
		return nil, diags
	}
	obj := model.Object{Type: model.ObjectDatabase, Database: blk.Database}
	if blk.Schema != nil {
		if engine != model.EnginePostgres {
			return nil, append(diags, errAt(b.DefRange, "Unsupported attribute", `"schema" is only supported for postgres.`))
		}
		obj = model.Object{Type: model.ObjectSchema, Database: blk.Database, Schema: *blk.Schema}
	}
	if len(blk.Privileges) == 0 {
		return nil, append(diags, errAt(b.DefRange, "Empty privileges", "privileges must not be empty."))
	}
	names, err := ExpandPrivileges(engine, obj.Type, blk.Privileges)
	if err != nil {
		return nil, append(diags, errAt(b.DefRange, "Invalid privilege", err.Error()))
	}
	grantee := ParseRoleID(blk.Role, engine)
	out := make([]model.Privilege, 0, len(names))
	for _, n := range names {
		out = append(out, model.Privilege{Grantee: grantee, Object: obj, Name: n, GrantOption: blk.WithGrantOption != nil && *blk.WithGrantOption})
	}
	return out, diags
}

// Privileges grantable per engine and object type, in canonical order.
var privileges = map[model.Engine]map[model.ObjectType][]string{
	model.EnginePostgres: {
		model.ObjectDatabase: {"CONNECT", "CREATE", "TEMPORARY"},
		model.ObjectSchema:   {"CREATE", "USAGE"},
	},
	model.EngineMySQL: {
		model.ObjectDatabase: {
			"ALTER", "ALTER ROUTINE", "CREATE", "CREATE ROUTINE", "CREATE TEMPORARY TABLES", "CREATE VIEW",
			"DELETE", "DROP", "EVENT", "EXECUTE", "INDEX", "INSERT", "LOCK TABLES", "REFERENCES",
			"SELECT", "SHOW VIEW", "TRIGGER", "UPDATE",
		},
	},
}

// ExpandPrivileges normalizes privilege names and expands ALL.
func ExpandPrivileges(engine model.Engine, typ model.ObjectType, in []string) ([]string, error) {
	valid := privileges[engine][typ]
	set := map[string]bool{}
	for _, p := range in {
		n := model.NormalizePrivilege(p)
		switch {
		case n == "ALL" || n == "ALL PRIVILEGES":
			for _, v := range valid {
				set[v] = true
			}
			continue
		case n == "TEMP" && engine == model.EnginePostgres:
			n = "TEMPORARY"
		}
		if !slices.Contains(valid, n) {
			return nil, fmt.Errorf("privilege %q is not valid on a %s %s (valid: %s)", p, engine, typ, strings.Join(valid, ", "))
		}
		set[n] = true
	}
	out := make([]string, 0, len(set))
	for _, v := range valid {
		if set[v] {
			out = append(out, v)
		}
	}
	return out, nil
}

func checkEngineOnly(b *hcl.Block, engine model.Engine, pgOnly, mysqlOnly map[string]bool) hcl.Diagnostics {
	var diags hcl.Diagnostics
	check := func(attrs map[string]bool, want model.Engine) {
		if engine == want {
			return
		}
		for _, name := range slices.Sorted(maps.Keys(attrs)) {
			if attrs[name] {
				diags = append(diags, errAt(b.DefRange, "Unsupported attribute", fmt.Sprintf("%q is only supported for %s.", name, want)))
			}
		}
	}
	check(pgOnly, model.EnginePostgres)
	check(mysqlOnly, model.EngineMySQL)
	return diags
}

func validate(d *model.Desired) hcl.Diagnostics {
	var diags hcl.Diagnostics
	fail := func(format string, args ...any) {
		diags = append(diags, &hcl.Diagnostic{Severity: hcl.DiagError, Summary: "Invalid configuration", Detail: fmt.Sprintf(format, args...)})
	}
	dbs := map[string]bool{}
	for _, db := range d.Databases {
		if dbs[db.Name] {
			fail("database %q is declared more than once", db.Name)
		}
		dbs[db.Name] = true
	}
	roles := map[model.RoleID]bool{}
	for _, r := range d.Roles {
		if roles[r.ID] {
			fail("role %q is declared more than once", r.ID)
		}
		roles[r.ID] = true
	}
	schemas := map[[2]string]bool{}
	for _, s := range d.Schemas {
		if !dbs[s.Database] {
			fail("schema %q belongs to database %q, which is not declared", s.Name, s.Database)
		}
		key := [2]string{s.Database, s.Name}
		if schemas[key] {
			fail("schema %q in database %q is declared more than once", s.Name, s.Database)
		}
		schemas[key] = true
	}
	seen := map[model.PrivilegeKey]bool{}
	for _, p := range d.Privileges {
		if !dbs[p.Object.Database] {
			fail("grant to %q targets database %q, which is not declared", p.Grantee, p.Object.Database)
		}
		if p.Object.Type == model.ObjectSchema && !schemas[[2]string{p.Object.Database, p.Object.Schema}] {
			fail("grant to %q targets schema %q, which is not declared", p.Grantee, p.Object)
		}
		if !roles[p.Grantee] {
			fail("grant targets role %q, which is not declared", p.Grantee)
		}
		if seen[p.Key()] {
			fail("privilege %s on %s to %q is granted more than once", p.Name, p.Object, p.Grantee)
		}
		seen[p.Key()] = true
	}
	return diags
}

func errAt(rng hcl.Range, summary, detail string) *hcl.Diagnostic {
	return &hcl.Diagnostic{Severity: hcl.DiagError, Summary: summary, Detail: detail, Subject: rng.Ptr()}
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

func derefSlice[T any](p *[]T) []T {
	if p == nil {
		return nil
	}
	return *p
}
