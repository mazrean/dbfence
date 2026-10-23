// Package config loads dbfence HCL configuration into the desired model.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
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
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("configuration file %s not found (use -f/--file or DBFENCE_FILE): %w", path, err)
	}
	if err != nil {
		return nil, fmt.Errorf("read configuration %s: %w", path, err)
	}
	if !st.IsDir() {
		return []string{path}, nil
	}
	// os.ReadDir instead of filepath.Glob: the directory name must not be
	// interpreted as a pattern.
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("read configuration directory %s: %w", path, err)
	}
	var files []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".hcl") {
			continue
		}
		f := filepath.Join(path, e.Name())
		// Stat follows symlinks, so a link to a file still counts.
		if fi, err := os.Stat(f); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no *.hcl files in %s", path)
	}
	slices.Sort(files)
	return files, nil
}

// diagError renders the error diagnostics. The leading "Error: " of the
// first one is dropped because the CLI prefixes errors with it already.
func diagError(p *hclparse.Parser, diags hcl.Diagnostics) error {
	diags = dropCascades(errorsOnly(diags))
	// gohcl decodes attributes in map order; report in source order.
	slices.SortStableFunc(diags, func(a, b *hcl.Diagnostic) int {
		switch {
		case a.Subject == nil || b.Subject == nil:
			return cmpBool(a.Subject != nil, b.Subject != nil)
		case a.Subject.Filename != b.Subject.Filename:
			return strings.Compare(a.Subject.Filename, b.Subject.Filename)
		default:
			return a.Subject.Start.Byte - b.Subject.Start.Byte
		}
	})
	var sb strings.Builder
	w := hcl.NewDiagnosticTextWriter(&sb, p.Files(), 0, false)
	if err := w.WriteDiagnostics(diags); err != nil {
		return diags
	}
	return errors.New(strings.TrimPrefix(strings.TrimRight(sb.String(), "\n"), "Error: "))
}

// cmpBool orders false before true.
func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	default:
		return -1
	}
}

func errorsOnly(diags hcl.Diagnostics) hcl.Diagnostics {
	var out hcl.Diagnostics
	for _, d := range diags {
		if d.Severity == hcl.DiagError {
			out = append(out, d)
		}
	}
	return out
}

// dropCascades removes the "value must be known" diagnostics gohcl emits
// when converting the placeholder of an expression that already failed.
func dropCascades(diags hcl.Diagnostics) hcl.Diagnostics {
	isCascade := func(d *hcl.Diagnostic) bool {
		return d.Summary == "Unsuitable value type" && strings.Contains(d.Detail, "value must be known") && d.Context != nil
	}
	var out hcl.Diagnostics
	for _, d := range diags {
		if isCascade(d) && slices.ContainsFunc(diags, func(o *hcl.Diagnostic) bool {
			return o != d && !isCascade(o) && o.Subject != nil && d.Context.Overlaps(*o.Subject)
		}) {
			continue
		}
		out = append(out, d)
	}
	return out
}

// resource is a labeled block awaiting full decode.
type resource struct {
	block *hcl.Block
	attrs hcl.Attributes
	name  string
	host  string
	// nameRange is the name attribute, or the label when name is absent.
	nameRange hcl.Range
}

// decoded holds the decoded objects together with their source so that
// validation can point at the offending block or attribute.
type decoded struct {
	engine    model.Engine
	databases []decodedDatabase
	roles     []decodedRole
	schemas   []decodedSchema
	grants    []decodedGrant
	ignore    model.Ignore
}

type decodedDatabase struct {
	db  model.Database
	res resource
}

type decodedRole struct {
	role model.Role
	typ  string
	// hostless lists MySQL member_of entries written without a host,
	// which therefore default to %.
	hostless []model.RoleID
	res      resource
}

type decodedSchema struct {
	schema model.Schema
	res    resource
}

type decodedGrant struct {
	block   *hcl.Block
	attrs   hcl.Attributes
	grantee model.RoleID
	object  model.Object
	names   []string
	option  bool
}

func (d *decoded) desired() *model.Desired {
	out := &model.Desired{Engine: d.engine, Ignore: d.ignore}
	for _, db := range d.databases {
		out.Databases = append(out.Databases, db.db)
	}
	for _, r := range d.roles {
		out.Roles = append(out.Roles, r.role)
	}
	for _, s := range d.schemas {
		out.Schemas = append(out.Schemas, s.schema)
	}
	for _, g := range d.grants {
		for _, n := range g.names {
			out.Privileges = append(out.Privileges, model.Privilege{Grantee: g.grantee, Object: g.object, Name: n, GrantOption: g.option})
		}
	}
	return out
}

func decode(body hcl.Body, fns map[string]function.Function) (*Config, hcl.Diagnostics) {
	content, diags := body.Content(rootSchema)
	if diags.HasErrors() {
		return nil, diags
	}
	base := &hcl.EvalContext{Functions: fns}

	var conn *connectionBlock
	var connBlock *hcl.Block
	byType := map[string][]*hcl.Block{}
	for _, b := range content.Blocks {
		if b.Type == "connection" {
			if connBlock != nil {
				diags = append(diags, errAt(b.DefRange, "Duplicate connection block",
					fmt.Sprintf("Only one connection block is allowed; the first one is at %s.", loc(connBlock.DefRange))))
				continue
			}
			connBlock, conn = b, &connectionBlock{}
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
	connAttrs, _ := connBlock.Body.JustAttributes()
	engine := model.Engine(conn.Engine)
	if engine != model.EngineMySQL && engine != model.EnginePostgres {
		return nil, append(diags, errAt(attrRange(connAttrs, "engine", connBlock.DefRange), "Unsupported engine",
			fmt.Sprintf("engine must be %q or %q, got %q.", model.EngineMySQL, model.EnginePostgres, conn.Engine)))
	}

	// Pass 1: resolve names so blocks can reference each other.
	vars := map[string]map[string]cty.Value{}
	first := map[string]map[string]*hcl.Block{}
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
				first[refType] = map[string]*hcl.Block{}
			}
			if prev, dup := first[refType][b.Labels[0]]; dup {
				detail := fmt.Sprintf("%s %q is defined more than once; the first definition is %s %q at %s.", typ, b.Labels[0], prev.Type, b.Labels[0], loc(prev.LabelRanges[0]))
				if prev.Type != typ {
					detail += " role and user blocks share a namespace."
				}
				diags = append(diags, errAt(b.LabelRanges[0], "Duplicate label", detail))
				continue
			}
			first[refType][b.Labels[0]] = b
			vars[refType][b.Labels[0]] = refValue(typ, r, engine, refContext(base, vars))
			resources[typ] = append(resources[typ], r)
		}
	}
	diags = append(diags, resolveSchemaDatabases(base, vars, resources["schema"], engine)...)
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

	// Pass 2: full decode. Each block is checked on its own so that one
	// faulty block does not hide the errors of the others.
	dec := &decoded{engine: engine}
	for _, r := range resources["database"] {
		db, dd := decodeDatabase(r, ctx, engine)
		diags = append(diags, dd...)
		if !dd.HasErrors() {
			dec.databases = append(dec.databases, decodedDatabase{res: r, db: db})
		}
	}
	for _, typ := range []string{"role", "user"} {
		for _, r := range resources[typ] {
			role, dd := decodeRole(r, typ, ctx, engine)
			diags = append(diags, dd...)
			if !dd.HasErrors() {
				dec.roles = append(dec.roles, role)
			}
		}
	}
	for _, r := range resources["schema"] {
		if engine != model.EnginePostgres {
			diags = append(diags, errAt(r.block.DefRange, "Unsupported block", "schema blocks are only supported for postgres; use database blocks for MySQL."))
			continue
		}
		var blk schemaBlock
		dd := gohcl.DecodeBody(r.block.Body, ctx, &blk)
		diags = append(diags, dd...)
		if dd.HasErrors() {
			continue
		}
		if dd := checkNotEmpty(r, map[string]*string{"owner": blk.Owner}); dd.HasErrors() {
			diags = append(diags, dd...)
			continue
		}
		dec.schemas = append(dec.schemas, decodedSchema{res: r, schema: model.Schema{Database: blk.Database, Name: r.name, Owner: deref(blk.Owner)}})
	}
	for _, b := range byType["grant"] {
		g, dd := decodeGrant(b, ctx, engine)
		diags = append(diags, dd...)
		if !dd.HasErrors() {
			dec.grants = append(dec.grants, g)
		}
	}
	for _, b := range byType["ignore"] {
		diags = append(diags, decodeIgnore(b, ctx, engine, &dec.ignore)...)
	}
	if diags.HasErrors() {
		return nil, diags
	}
	diags = append(diags, validate(dec)...)
	if diags.HasErrors() {
		return nil, diags
	}
	return &Config{Engine: engine, DSN: conn.DSN, Desired: dec.desired()}, diags
}

func resolveName(b *hcl.Block, ctx *hcl.EvalContext, engine model.Engine) (resource, hcl.Diagnostics) {
	r := resource{block: b, name: b.Labels[0], nameRange: b.LabelRanges[0]}
	attrs, diags := b.Body.JustAttributes()
	if diags.HasErrors() {
		return r, diags
	}
	r.attrs = attrs
	if a, ok := attrs["name"]; ok {
		r.nameRange = a.Range
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
		if r.host == "" && !diags.HasErrors() {
			diags = append(diags, errAt(a.Range, "Empty host", `host must not be empty; use "%" for any host.`))
		}
		// MySQL stores host names in lower case.
		r.host = strings.ToLower(r.host)
	} else if engine == model.EngineMySQL && (b.Type == "role" || b.Type == "user") {
		r.host = "%"
	}
	if diags.HasErrors() {
		return r, diags
	}
	if r.name == "" {
		return r, append(diags, errAt(r.nameRange, "Empty name", "Object names must not be empty."))
	}
	return r, append(diags, checkName(r, engine)...)
}

// refValue is the value exposed to expressions as <type>.<label>.
func refValue(typ string, r resource, engine model.Engine, ctx *hcl.EvalContext) cty.Value {
	switch typ {
	case "role", "user":
		id := r.name
		if engine == model.EngineMySQL {
			id = model.RoleID{Name: r.name, Host: r.host}.String()
		}
		return cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal(r.name), "host": cty.StringVal(r.host), "id": cty.StringVal(id)})
	case "schema":
		// Schemas may only reference databases, which are resolved first.
		db := cty.UnknownVal(cty.String)
		if a, ok := r.attrs["database"]; ok {
			if v, d := a.Expr.Value(ctx); !d.HasErrors() {
				if sv, err := convert.Convert(v, cty.String); err == nil && !sv.IsNull() {
					db = sv
				}
			}
		}
		return cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal(r.name), "database": db})
	default:
		return cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal(r.name)})
	}
}

// resolveSchemaDatabases resolves schema.<label>.database references
// between schemas regardless of declaration order, and reports references
// that cannot be resolved instead of leaving an unknown value behind.
func resolveSchemaDatabases(base *hcl.EvalContext, vars map[string]map[string]cty.Value, schemas []resource, engine model.Engine) hcl.Diagnostics {
	pending := func(r resource) bool { return !vars["schema"][r.block.Labels[0]].GetAttr("database").IsKnown() }
	for changed := true; changed; {
		changed = false
		ctx := refContext(base, vars)
		for _, r := range schemas {
			if !pending(r) {
				continue
			}
			if v := refValue("schema", r, engine, ctx); v.GetAttr("database").IsKnown() {
				vars["schema"][r.block.Labels[0]] = v
				changed = true
			}
		}
	}
	var diags hcl.Diagnostics
	ctx := refContext(base, vars)
	for _, r := range schemas {
		a, ok := r.attrs["database"]
		if !ok || !pending(r) {
			// A missing database is reported by the full decode.
			continue
		}
		v, d := a.Expr.Value(ctx)
		switch {
		case d.HasErrors():
			diags = append(diags, d...)
		case !v.IsWhollyKnown():
			diags = append(diags, errAt(a.Range, "Cyclic reference",
				fmt.Sprintf("the database of schema %q cannot be resolved: it depends on itself through schema.<label>.database references.", r.block.Labels[0])))
		}
	}
	return diags
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

func decodeDatabase(r resource, ctx *hcl.EvalContext, engine model.Engine) (model.Database, hcl.Diagnostics) {
	var blk databaseBlock
	diags := gohcl.DecodeBody(r.block.Body, ctx, &blk)
	if diags.HasErrors() {
		return model.Database{}, diags
	}
	diags = append(diags, checkEngineOnly(r, engine, map[string]bool{
		"owner": blk.Owner != nil, "encoding": blk.Encoding != nil, "lc_collate": blk.LcCollate != nil, "lc_ctype": blk.LcCtype != nil,
	}, map[string]bool{"charset": blk.Charset != nil, "collation": blk.Collation != nil})...)
	if engine == model.EnginePostgres {
		diags = append(diags, checkNotEmpty(r, map[string]*string{"owner": blk.Owner, "encoding": blk.Encoding, "lc_collate": blk.LcCollate, "lc_ctype": blk.LcCtype})...)
	} else {
		diags = append(diags, checkSimpleIdent(r, map[string]*string{"charset": blk.Charset, "collation": blk.Collation})...)
	}
	return model.Database{
		Name: r.name, Owner: deref(blk.Owner), Encoding: deref(blk.Encoding), LcCollate: deref(blk.LcCollate),
		LcCtype: deref(blk.LcCtype), Charset: deref(blk.Charset), Collation: deref(blk.Collation),
	}, diags
}

func decodeRole(r resource, typ string, ctx *hcl.EvalContext, engine model.Engine) (decodedRole, hcl.Diagnostics) {
	out := decodedRole{typ: typ, res: r}
	var blk roleBlock
	diags := gohcl.DecodeBody(r.block.Body, ctx, &blk)
	if diags.HasErrors() {
		return out, diags
	}
	diags = append(diags, checkEngineOnly(r, engine, map[string]bool{
		"superuser": blk.Superuser != nil, "createdb": blk.CreateDB != nil, "createrole": blk.CreateRole != nil,
		"inherit": blk.Inherit != nil, "replication": blk.Replication != nil, "bypassrls": blk.BypassRLS != nil,
		"connection_limit": blk.ConnectionLimit != nil,
	}, map[string]bool{"auth_plugin": blk.AuthPlugin != nil})...)
	if engine == model.EngineMySQL {
		diags = append(diags, checkSimpleIdent(r, map[string]*string{"auth_plugin": blk.AuthPlugin})...)
	} else if l := blk.ConnectionLimit; l != nil && (*l < -1 || *l > math.MaxInt32) {
		diags = append(diags, errAt(attrRange(r.attrs, "connection_limit", r.block.DefRange), "Invalid connection_limit",
			fmt.Sprintf("connection_limit must be -1 (unlimited) or between 0 and %d, got %d.", math.MaxInt32, *l)))
	}
	diags = append(diags, checkPassword(r, typ, blk.Password, engine)...)
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
		rng := attrRange(r.attrs, "member_of", r.block.DefRange)
		seen := map[model.RoleID]bool{}
		for _, m := range *blk.MemberOf {
			id := ParseRoleID(m, engine)
			switch {
			case engine == model.EngineMySQL && id.Host == "":
				diags = append(diags, errAt(rng, "Empty host",
					fmt.Sprintf(`member_of entry %q has an empty host; use "name@%%" or role.<label>.id.`, m)))
			case id == role.ID:
				diags = append(diags, errAt(rng, "Membership cycle", fmt.Sprintf("role %q cannot be a member of itself.", id)))
			case seen[id]:
				diags = append(diags, errAt(rng, "Duplicate membership", fmt.Sprintf("member_of lists role %q more than once.", id)))
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			if engine == model.EngineMySQL && !strings.Contains(m, "@") {
				out.hostless = append(out.hostless, id)
			}
			role.MemberOf = append(role.MemberOf, id)
		}
		model.SortRoleIDs(role.MemberOf)
	}
	out.role = role
	return out, diags
}

// ParseRoleID parses "name" or, for MySQL, "name@host" (host defaults to %
// and is lower-cased, as MySQL stores it).
func ParseRoleID(s string, engine model.Engine) model.RoleID {
	if engine != model.EngineMySQL {
		return model.RoleID{Name: s}
	}
	if name, host, ok := strings.CutLast(s, "@"); ok {
		return model.RoleID{Name: name, Host: strings.ToLower(host)}
	}
	return model.RoleID{Name: s, Host: "%"}
}

func decodeGrant(b *hcl.Block, ctx *hcl.EvalContext, engine model.Engine) (decodedGrant, hcl.Diagnostics) {
	g := decodedGrant{block: b}
	var blk grantBlock
	diags := gohcl.DecodeBody(b.Body, ctx, &blk)
	if diags.HasErrors() {
		return g, diags
	}
	g.attrs, _ = b.Body.JustAttributes()
	g.object = model.Object{Type: model.ObjectDatabase, Database: blk.Database}
	if blk.Schema != nil {
		if engine != model.EnginePostgres {
			return g, append(diags, errAt(attrRange(g.attrs, "schema", b.DefRange), "Unsupported attribute", `"schema" is only supported for postgres.`))
		}
		g.object = model.Object{Type: model.ObjectSchema, Database: blk.Database, Schema: *blk.Schema}
	}
	privRange := attrRange(g.attrs, "privileges", b.DefRange)
	if len(blk.Privileges) == 0 {
		return g, append(diags, errAt(privRange, "Empty privileges", "privileges must not be empty."))
	}
	names, err := ExpandPrivileges(engine, g.object.Type, blk.Privileges)
	if err != nil {
		return g, append(diags, errAt(privRange, "Invalid privilege", err.Error()))
	}
	g.grantee = ParseRoleID(blk.Role, engine)
	if engine == model.EngineMySQL && g.grantee.Host == "" {
		return g, append(diags, errAt(attrRange(g.attrs, "role", b.DefRange), "Empty host",
			fmt.Sprintf(`role %q has an empty host; use "name@%%" or user.<label>.id.`, blk.Role)))
	}
	g.names = names
	g.option = blk.WithGrantOption != nil && *blk.WithGrantOption
	return g, diags
}

func decodeIgnore(b *hcl.Block, ctx *hcl.EvalContext, engine model.Engine, ig *model.Ignore) hcl.Diagnostics {
	var blk ignoreBlock
	diags := gohcl.DecodeBody(b.Body, ctx, &blk)
	if diags.HasErrors() {
		return diags
	}
	attrs, _ := b.Body.JustAttributes()
	diags = append(diags, checkEngineOnly(resource{block: b, attrs: attrs}, engine, map[string]bool{"schemas": blk.Schemas != nil}, nil)...)
	for _, l := range []struct {
		dst  *[]string
		src  *[]string
		name string
	}{{&ig.Roles, blk.Roles, "roles"}, {&ig.Databases, blk.Databases, "databases"}, {&ig.Schemas, blk.Schemas, "schemas"}} {
		for _, p := range derefSlice(l.src) {
			// Anchored exactly like diff compiles ignore patterns.
			if _, err := regexp.Compile("^(?:" + p + ")$"); err != nil {
				diags = append(diags, errAt(attrRange(attrs, l.name, b.DefRange), "Invalid ignore pattern", fmt.Sprintf("%s pattern %q: %v", l.name, p, err)))
			}
		}
		*l.dst = append(*l.dst, derefSlice(l.src)...)
	}
	return diags
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

func checkEngineOnly(r resource, engine model.Engine, pgOnly, mysqlOnly map[string]bool) hcl.Diagnostics {
	var diags hcl.Diagnostics
	check := func(attrs map[string]bool, want model.Engine) {
		if engine == want {
			return
		}
		for _, name := range slices.Sorted(maps.Keys(attrs)) {
			if attrs[name] {
				diags = append(diags, errAt(attrRange(r.attrs, name, r.block.DefRange), "Unsupported attribute", fmt.Sprintf("%q is only supported for %s.", name, want)))
			}
		}
	}
	check(pgOnly, model.EnginePostgres)
	check(mysqlOnly, model.EngineMySQL)
	return diags
}

// Identifier length limits.
const (
	pgMaxIdentBytes   = 63 // NAMEDATALEN - 1
	mysqlMaxUserChars = 32
	mysqlMaxDBChars   = 64
	mysqlMaxHostChars = 255
)

// checkName checks the engine's identifier limits.
func checkName(r resource, engine model.Engine) hcl.Diagnostics {
	var diags hcl.Diagnostics
	typ := r.block.Type
	isRole := typ == "role" || typ == "user"
	tooLong := func(rng hcl.Range, what, v string, n, limit int, unit string) {
		diags = append(diags, errAt(rng, "Name too long",
			fmt.Sprintf("%s %q is %d %s long; %s allows at most %d.", what, v, n, unit, engine, limit)))
	}
	switch engine {
	case model.EnginePostgres:
		// Longer names are silently truncated (NAMEDATALEN - 1).
		if n := len(r.name); n > pgMaxIdentBytes {
			tooLong(r.nameRange, typ+" name", r.name, n, pgMaxIdentBytes, "bytes")
		}
		if isRole && (r.name == "public" || r.name == "none" || strings.HasPrefix(r.name, "pg_")) {
			diags = append(diags, errAt(r.nameRange, "Reserved name",
				fmt.Sprintf(`%s name %q is reserved by PostgreSQL ("public", "none" and names starting with "pg_").`, typ, r.name)))
		}
	case model.EngineMySQL:
		limit := mysqlMaxDBChars
		if isRole {
			limit = mysqlMaxUserChars
		}
		if n := utf8.RuneCountInString(r.name); n > limit {
			tooLong(r.nameRange, typ+" name", r.name, n, limit, "characters")
		}
		if n := utf8.RuneCountInString(r.host); isRole && n > mysqlMaxHostChars {
			tooLong(attrRange(r.attrs, "host", r.block.DefRange), "host", r.host, n, mysqlMaxHostChars, "characters")
		}
	}
	return diags
}

// checkPassword rejects passwords the server cannot store. The diagnostics
// carry no source range: the snippet would print the password.
func checkPassword(r resource, typ string, pw *string, engine model.Engine) hcl.Diagnostics {
	if pw == nil {
		return nil
	}
	fail := func(summary, detail string) hcl.Diagnostics {
		return hcl.Diagnostics{{Severity: hcl.DiagError, Summary: summary,
			Detail: fmt.Sprintf("%s %q at %s: %s", typ, r.block.Labels[0], loc(r.block.DefRange), detail)}}
	}
	switch {
	case strings.ContainsRune(*pw, 0):
		return fail("Invalid password", "password must not contain NUL characters.")
	case *pw == "" && engine == model.EnginePostgres:
		return fail("Empty password", "an empty password is not valid on PostgreSQL (it clears the password); omit password to leave it unmanaged.")
	}
	return nil
}

// checkNotEmpty rejects set but empty attributes, which would otherwise
// silently mean "unmanaged".
func checkNotEmpty(r resource, attrs map[string]*string) hcl.Diagnostics {
	var diags hcl.Diagnostics
	for _, name := range slices.Sorted(maps.Keys(attrs)) {
		if v := attrs[name]; v != nil && *v == "" {
			diags = append(diags, errAt(attrRange(r.attrs, name, r.block.DefRange), "Empty value",
				fmt.Sprintf("%s must not be empty; omit the attribute to leave it unmanaged.", name)))
		}
	}
	return diags
}

var simpleIdent = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// checkSimpleIdent checks MySQL charset, collation and plugin names.
func checkSimpleIdent(r resource, attrs map[string]*string) hcl.Diagnostics {
	var diags hcl.Diagnostics
	for _, name := range slices.Sorted(maps.Keys(attrs)) {
		if v := attrs[name]; v != nil && !simpleIdent.MatchString(*v) {
			diags = append(diags, errAt(attrRange(r.attrs, name, r.block.DefRange), "Invalid "+name,
				fmt.Sprintf("%s must consist of letters, digits and underscores, got %q.", name, *v)))
		}
	}
	return diags
}

// attrRange is the range of the named attribute, or fallback when absent.
func attrRange(attrs hcl.Attributes, name string, fallback hcl.Range) hcl.Range {
	if a, ok := attrs[name]; ok {
		return a.Range
	}
	return fallback
}

// loc formats the start of rng for diagnostic details.
func loc(rng hcl.Range) string {
	return fmt.Sprintf("%s:%d,%d", rng.Filename, rng.Start.Line, rng.Start.Column)
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
