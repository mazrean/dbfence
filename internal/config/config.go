// Package config loads dbfence HCL configuration into the desired model.
package config

import (
	"errors"
	"fmt"
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
	"github.com/mazrean/dbfence/internal/funcs"
	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/password"
	"github.com/mazrean/dbfence/internal/secret"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"
)

// Config is a loaded configuration.
type Config struct {
	Desired    *model.Desired
	Connection model.Connection
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
	Name            *string        `hcl:"name"`
	Host            *string        `hcl:"host"`
	Login           *bool          `hcl:"login"`
	Password        *string        `hcl:"password"`
	MemberOf        hcl.Expression `hcl:"member_of"`
	Superuser       *bool          `hcl:"superuser"`
	CreateDB        *bool          `hcl:"createdb"`
	CreateRole      *bool          `hcl:"createrole"`
	Inherit         *bool          `hcl:"inherit"`
	Replication     *bool          `hcl:"replication"`
	BypassRLS       *bool          `hcl:"bypassrls"`
	ConnectionLimit *int           `hcl:"connection_limit"`
	AuthPlugin      *string        `hcl:"auth_plugin"`
}

type schemaBlock struct {
	Name     *string `hcl:"name"`
	Owner    *string `hcl:"owner"`
	Database string  `hcl:"database"`
}

type grantBlock struct {
	Schema          *string  `hcl:"schema"`
	WithGrantOption *bool    `hcl:"with_grant_option"`
	Database        *string  `hcl:"database"`
	DatabasePattern *string  `hcl:"database_pattern"`
	Role            string   `hcl:"role"`
	Privileges      []string `hcl:"privileges"`
}

type ignoreBlock struct {
	Roles     *[]string `hcl:"roles"`
	Databases *[]string `hcl:"databases"`
	Schemas   *[]string `hcl:"schemas"`
}

// Load parses every *.hcl file directly in dir, like Terraform.
func Load(dir string, fns map[string]function.Function) (*Config, error) {
	files, err := hclFiles(dir)
	if err != nil {
		return nil, err
	}
	// Relative tfstate paths resolve against the configuration directory.
	fns = funcs.ResolvePathsFrom(fns, dir)
	// Engine names are printed by design, even when a password equals one.
	secret.RegisterPublic(string(model.EnginePostgres))
	secret.RegisterPublic(string(model.EngineMySQL))
	parser := hclparse.NewParser()
	var bodies []*hcl.File
	var diags hcl.Diagnostics
	for _, f := range files {
		file, d := parser.ParseHCLFile(f)
		diags = append(diags, d...)
		if file != nil {
			// Even when parsing failed: the body holds what parsed.
			registerLiteralSecrets(file.Body)
			registerStateURLPasswords(file.Body)
			bodies = append(bodies, file)
		}
	}
	if diags.HasErrors() {
		return nil, diagError(parser, diags)
	}
	cfg, diags := decode(unmarkedBody{hcl.MergeFiles(bodies)}, fns)
	if diags.HasErrors() {
		return nil, diagError(parser, diags)
	}
	return cfg, nil
}

func hclFiles(dir string) ([]string, error) {
	// os.ReadDir instead of filepath.Glob: the directory name must not be
	// interpreted as a pattern.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read configuration directory (set -C/--chdir or DBFENCE_CHDIR): %w", err)
	}
	var files []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".hcl") {
			continue
		}
		f := filepath.Join(dir, e.Name())
		// Stat follows symlinks, so a link to a file still counts.
		if fi, err := os.Stat(f); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no *.hcl files in %s (set -C/--chdir or DBFENCE_CHDIR)", dir)
	}
	slices.Sort(files)
	return files, nil
}

// diagError renders the error diagnostics. The leading "Error: " of the
// first one is dropped because the CLI prefixes errors with it already.
// Source snippets show the values of password masked (see
// maskSecrets).
func diagError(p *hclparse.Parser, diags hcl.Diagnostics) error {
	diags = hideSecretKeys(dropCascades(errorsOnly(diags)))
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
	w := hcl.NewDiagnosticTextWriter(&sb, maskedFiles(p.Files()), 0, false)
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

// hideSecretKeys rewrites the duplicate key errors of for expressions
// whose key is secret-derived: HCL quotes the key in Detail even when it
// is marked. The key expression is evaluated again in the context of the
// failing iteration to find its marks; secret lookups are cached, so this
// does not fetch them again.
func hideSecretKeys(diags hcl.Diagnostics) hcl.Diagnostics {
	out := make(hcl.Diagnostics, len(diags))
	for i, d := range diags {
		out[i] = d
		if d.Summary != "Duplicate object key" || d.Expression == nil || d.EvalContext == nil {
			continue
		}
		if v, vd := d.Expression.Value(d.EvalContext); !vd.HasErrors() && !v.ContainsMarked() {
			continue
		}
		nd := *d
		nd.Detail = "Two different items produced the same key in this 'for' expression; the key is not shown because it is derived from a secret value. If duplicates are expected, use the ellipsis (...) after the value expression to enable grouping by key."
		out[i] = &nd
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
	// nameMarks and hostMarks are the cty marks (funcs.Sensitive) of
	// name and host, put back on the reference values.
	nameMarks cty.ValueMarks
	hostMarks cty.ValueMarks
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
		if g.grantee.IsPublic() && !slices.Contains(out.PublicObjects, g.object) {
			out.PublicObjects = append(out.PublicObjects, g.object)
		}
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

	var conn model.Connection
	var connBlock *hcl.Block
	byType := map[string][]*hcl.Block{}
	for _, b := range content.Blocks {
		if b.Type == "connection" {
			if connBlock != nil {
				diags = append(diags, errAt(b.DefRange, "Duplicate connection block",
					fmt.Sprintf("Only one connection block is allowed; the first one is at %s.", loc(connBlock.DefRange))))
				continue
			}
			var d hcl.Diagnostics
			connBlock = b
			conn, d = decodeConnection(b, base)
			diags = append(diags, d...)
			continue
		}
		byType[b.Type] = append(byType[b.Type], b)
	}
	if connBlock == nil {
		return nil, append(diags, &hcl.Diagnostic{Severity: hcl.DiagError, Summary: "Missing connection block", Detail: `A connection block with "engine", "host" and "user" is required.`})
	}
	if diags.HasErrors() {
		return nil, diags
	}
	engine := conn.Engine

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
	return &Config{Connection: conn, Desired: dec.desired()}, diags
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
		r.nameMarks = make(cty.ValueMarks)
		diags = append(diags, decodeLiteral(a, ctx, &r.name, r.nameMarks)...)
	}
	if a, ok := attrs["host"]; ok {
		if b.Type != "role" && b.Type != "user" {
			return r, diags
		}
		if engine != model.EngineMySQL {
			return r, append(diags, errAt(a.Range, "Unsupported attribute", `"host" is only supported for mysql.`))
		}
		r.hostMarks = make(cty.ValueMarks)
		diags = append(diags, decodeLiteral(a, ctx, &r.host, r.hostMarks)...)
		switch {
		case diags.HasErrors():
		case r.host == "":
			diags = append(diags, errAt(a.Range, "Empty host", `host must not be empty; use "%" for any host.`))
		case strings.Contains(r.host, "@"):
			// Ids are name@host split at the last "@" (names may contain
			// one), so role.<label>.id would name another account.
			diags = append(diags, errAt(a.Range, "Invalid host", `host must not contain "@"; role ids are written name@host.`))
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

// decodeLiteral decodes name and host, which are resolved before any
// block can be referenced. The marks of the value are added to marks.
func decodeLiteral(a *hcl.Attribute, ctx *hcl.EvalContext, dst *string, marks cty.ValueMarks) hcl.Diagnostics {
	if len(a.Expr.Variables()) > 0 {
		return hcl.Diagnostics{errAt(a.Expr.Range(), "References not allowed",
			fmt.Sprintf("%s cannot reference other blocks; only literals and functions are allowed.", a.Name))}
	}
	return gohcl.DecodeExpression(markRecorder{Expression: markedExpr(a.Expr), marks: marks}, ctx, dst)
}

// markRecorder evaluates to the value of its expression without marks,
// and adds the marks to marks.
type markRecorder struct {
	hcl.Expression
	marks cty.ValueMarks
}

func (e markRecorder) Value(ctx *hcl.EvalContext) (cty.Value, hcl.Diagnostics) {
	v, diags := e.Expression.Value(ctx)
	v, m := v.UnmarkDeep()
	maps.Copy(e.marks, m)
	return v, diags
}

// markedExpr undoes unmarkedExpr, for the values that keep their marks.
func markedExpr(expr hcl.Expression) hcl.Expression {
	if u, ok := expr.(unmarkedExpr); ok {
		return u.Expression
	}
	return expr
}

// refValue is the value exposed to expressions as <type>.<label>. Names
// and hosts derived from a secret keep its mark, so that errors about the
// references do not show them.
func refValue(typ string, r resource, engine model.Engine, ctx *hcl.EvalContext) cty.Value {
	name := cty.StringVal(r.name).WithMarks(r.nameMarks)
	switch typ {
	case "role", "user":
		id := name
		if engine == model.EngineMySQL {
			id = cty.StringVal(model.RoleID{Name: r.name, Host: r.host}.String()).WithMarks(r.nameMarks, r.hostMarks)
		}
		return cty.ObjectVal(map[string]cty.Value{"name": name, "host": cty.StringVal(r.host).WithMarks(r.hostMarks), "id": id})
	case "schema":
		// Schemas may only reference databases, which are resolved first.
		db := cty.UnknownVal(cty.String)
		if a, ok := r.attrs["database"]; ok {
			if v, d := markedExpr(a.Expr).Value(ctx); !d.HasErrors() {
				if sv, err := convert.Convert(v, cty.String); err == nil && !sv.IsNull() {
					db = sv
				}
			}
		}
		return cty.ObjectVal(map[string]cty.Value{"name": name, "database": db})
	default:
		return cty.ObjectVal(map[string]cty.Value{"name": name})
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
	if blk.Password != nil {
		// Output redacts it wherever it appears (see secret.Writer).
		secret.Register(*blk.Password)
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
	members, managed, dd := decodeMemberOf(blk.MemberOf, ctx, engine)
	diags = append(diags, dd...)
	if managed {
		role.MemberOf = []model.RoleID{}
		rng := attrRange(r.attrs, "member_of", r.block.DefRange)
		seen := map[model.RoleID]bool{}
		for _, e := range members {
			m := e.role
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
			if e.opts != (model.MembershipOptions{}) {
				if role.MemberOptions == nil {
					role.MemberOptions = map[model.RoleID]model.MembershipOptions{}
				}
				role.MemberOptions[id] = e.opts
			}
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
	obj, d := decodeGrantObject(b, g.attrs, blk, engine)
	if d.HasErrors() {
		return g, append(diags, d...)
	}
	g.object = obj
	privRange := attrRange(g.attrs, "privileges", b.DefRange)
	roleRange := attrRange(g.attrs, "role", b.DefRange)
	public := strings.EqualFold(blk.Role, "public")
	g.option = blk.WithGrantOption != nil && *blk.WithGrantOption
	switch {
	case public && engine != model.EnginePostgres:
		return g, append(diags, errAt(roleRange, "Unsupported grantee",
			fmt.Sprintf(`role %q: grants to PUBLIC are only supported for postgres; to grant to an account named %q, use "%s@<host>" or user.<label>.id.`, blk.Role, blk.Role, blk.Role)))
	case public && g.option:
		return g, append(diags, errAt(attrRange(g.attrs, "with_grant_option", b.DefRange), "Invalid grant option",
			"PostgreSQL cannot give the grant option to PUBLIC; remove with_grant_option."))
	case len(blk.Privileges) == 0 && !public:
		return g, append(diags, errAt(privRange, "Empty privileges",
			`privileges must not be empty; only a grant to role = "PUBLIC" may use privileges = [] to revoke every privilege of PUBLIC.`))
	}
	names, err := ExpandPrivileges(engine, g.object.Type, blk.Privileges)
	if err != nil {
		return g, append(diags, errAt(privRange, "Invalid privilege", err.Error()))
	}
	g.names = names
	if public {
		g.grantee = model.PublicRole
		return g, diags
	}
	g.grantee = ParseRoleID(blk.Role, engine)
	if engine == model.EngineMySQL && g.grantee.Host == "" {
		return g, append(diags, errAt(attrRange(g.attrs, "role", b.DefRange), "Empty host",
			fmt.Sprintf(`role %q has an empty host; use "name@%%" or user.<label>.id.`, blk.Role)))
	}
	return g, diags
}

// decodeGrantObject returns the target of a grant block: exactly one of
// database and database_pattern, plus schema on PostgreSQL.
func decodeGrantObject(b *hcl.Block, attrs hcl.Attributes, blk grantBlock, engine model.Engine) (model.Object, hcl.Diagnostics) {
	switch {
	case blk.Database != nil && blk.DatabasePattern != nil:
		return model.Object{}, hcl.Diagnostics{errAt(attrRange(attrs, "database_pattern", b.DefRange), "Conflicting attributes",
			`a grant block takes either "database" or "database_pattern", not both.`)}
	case blk.DatabasePattern != nil:
		return decodeDatabasePattern(b, attrs, blk, engine)
	case blk.Database == nil:
		detail := `a grant block needs "database".`
		if engine == model.EngineMySQL {
			detail = `a grant block needs "database" or "database_pattern".`
		}
		return model.Object{}, hcl.Diagnostics{errAt(b.DefRange, "Missing required argument", detail)}
	case blk.Schema != nil:
		if engine != model.EnginePostgres {
			return model.Object{}, hcl.Diagnostics{errAt(attrRange(attrs, "schema", b.DefRange), "Unsupported attribute", `"schema" is only supported for postgres.`)}
		}
		return model.Object{Type: model.ObjectSchema, Database: *blk.Database, Schema: *blk.Schema}, nil
	}
	return model.Object{Type: model.ObjectDatabase, Database: *blk.Database}, nil
}

// maxMySQLDatabasePattern is the length of mysql.db.Db.
const maxMySQLDatabasePattern = model.MySQLMaxDatabaseChars

func decodeDatabasePattern(b *hcl.Block, attrs hcl.Attributes, blk grantBlock, engine model.Engine) (model.Object, hcl.Diagnostics) {
	rng := attrRange(attrs, "database_pattern", b.DefRange)
	p := *blk.DatabasePattern
	switch {
	case engine != model.EngineMySQL:
		return model.Object{}, hcl.Diagnostics{errAt(rng, "Unsupported attribute", `"database_pattern" is only supported for mysql.`)}
	case blk.Schema != nil:
		return model.Object{}, hcl.Diagnostics{errAt(attrRange(attrs, "schema", b.DefRange), "Unsupported attribute", `"schema" is only supported for postgres.`)}
	case utf8.RuneCountInString(p) > maxMySQLDatabasePattern:
		return model.Object{}, hcl.Diagnostics{errAt(rng, "Pattern too long",
			fmt.Sprintf("database_pattern %q is longer than %d characters.", p, maxMySQLDatabasePattern))}
	case !hasWildcard(p):
		return model.Object{}, hcl.Diagnostics{errAt(rng, "No wildcard",
			fmt.Sprintf(`database_pattern %q has no unescaped "%%" or "_"; use database for a single database.`, p))}
	}
	return model.Object{Type: model.ObjectDatabase, Pattern: p}, nil
}

// hasWildcard reports whether a MySQL LIKE pattern contains an unescaped
// % or _.
func hasWildcard(p string) bool {
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '\\':
			i++
		case '%', '_':
			return true
		}
	}
	return false
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
			// Compiled exactly like diff compiles ignore patterns.
			if _, err := model.CompileIgnorePattern(p); err != nil {
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
		case n == "GRANT OPTION" || n == "GRANT":
			return nil, fmt.Errorf("privilege %q cannot be listed in privileges; set with_grant_option = true instead", p)
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

// Identifier length limits, shared with the check of names read from
// the server (model.CheckName).
const (
	pgMaxIdentBytes   = model.PostgresMaxIdentBytes
	mysqlMaxUserChars = model.MySQLMaxUserChars
	mysqlMaxDBChars   = model.MySQLMaxDatabaseChars
	mysqlMaxHostChars = model.MySQLMaxHostChars
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
		switch {
		case isRole && (r.name == "public" || r.name == "none" || strings.HasPrefix(r.name, "pg_")):
			diags = append(diags, errAt(r.nameRange, "Reserved name",
				fmt.Sprintf(`%s name %q is reserved by PostgreSQL ("public", "none" and names starting with "pg_").`, typ, r.name)))
		case isRole && strings.EqualFold(r.name, "public"):
			diags = append(diags, errAt(r.nameRange, "Reserved name",
				fmt.Sprintf(`%s name %q is reserved: grant blocks read role = %q as the PUBLIC pseudo-role.`, typ, r.name, r.name)))
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
	case engine == model.EnginePostgres && password.PostgresVerifierKind(*pw) != password.VerifierUnknown:
		return fail("Password looks like a verifier", `PostgreSQL stores a password of the form "md5" + 32 characters or "SCRAM-SHA-256$..." as an already hashed verifier, so the role could not log in with it; choose another password.`)
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
