package provider

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	kepr "github.com/justdoGIT/kepr/sdk/go"
)

// fakeClient stands in for the daemon.
type fakeClient struct {
	vals  map[string]string
	infos map[string]*kepr.CredInfo
	sets  []kepr.SetOptions
}

func newFake() *fakeClient {
	return &fakeClient{vals: map[string]string{}, infos: map[string]*kepr.CredInfo{}}
}

func (f *fakeClient) Get(name string) (string, error) {
	if i := f.infos[name]; i == nil || i.Sealed {
		return "", errors.New("credential unavailable")
	}
	return f.vals[name], nil
}

func (f *fakeClient) Set(name, value string, o kepr.SetOptions) error {
	f.sets = append(f.sets, o)
	if value == "" {
		value = "generated-" + o.Generate
	}
	f.vals[name] = value
	info := &kepr.CredInfo{Name: name, Modified: "2026-10-05 08:00", RequiresConsent: o.RequiresConsent}
	if o.TTLSecs > 0 {
		info.ExpiresAt = "2026-10-05 09:00"
	}
	f.infos[name] = info
	return nil
}

func (f *fakeClient) Delete(name string) error {
	if f.infos[name] == nil {
		return errors.New("credential unavailable")
	}
	delete(f.infos, name)
	delete(f.vals, name)
	return nil
}

func (f *fakeClient) Info(name string) (*kepr.CredInfo, error) { return f.infos[name], nil }

// raw builds an object value for a schema type: listed attributes set, the
// rest null.
func raw(typ tftypes.Type, set map[string]any) tftypes.Value {
	obj := typ.(tftypes.Object)
	vals := map[string]tftypes.Value{}
	for k, at := range obj.AttributeTypes {
		vals[k] = tftypes.NewValue(at, set[k])
	}
	return tftypes.NewValue(obj, vals)
}

func TestProviderSchemasAreValid(t *testing.T) {
	ctx := context.Background()
	srv, err := providerserver.NewProtocol6WithError(New("test")())()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.GetProviderSchema(ctx, &tfprotov6.GetProviderSchemaRequest{})
	if err != nil || len(resp.Diagnostics) > 0 {
		t.Fatalf("%v %+v", err, resp.Diagnostics)
	}
	for _, s := range []*tfprotov6.Schema{resp.ResourceSchemas["kepr_secret"], resp.DataSourceSchemas["kepr_secret"]} {
		if s == nil {
			t.Fatal("kepr_secret missing")
		}
		for _, a := range s.Block.Attributes {
			if a.Name == "value" && !a.Sensitive {
				t.Fatal("value must be sensitive")
			}
			if a.Name == "name" && !a.Required {
				t.Fatal("name must be required")
			}
		}
	}
}

func TestValidators(t *testing.T) {
	ctx := context.Background()
	check := func(v validator.String, s string) bool {
		var resp validator.StringResponse
		v.ValidateString(ctx, validator.StringRequest{ConfigValue: types.StringValue(s)}, &resp)
		return !resp.Diagnostics.HasError()
	}
	if !check(nameValidator{}, "db_pass_1") || check(nameValidator{}, "../x") || check(nameValidator{}, "") ||
		check(nameValidator{}, strings.Repeat("A", 129)) {
		t.Fatal("name rule")
	}
	if !check(kindValidator{}, "words") || check(kindValidator{}, "rot13") {
		t.Fatal("kind rule")
	}
}

func resourceSchema(t *testing.T) (*secretResource, tfsdk.Plan, tftypes.Type) {
	ctx := context.Background()
	r := &secretResource{}
	var s resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &s)
	typ := s.Schema.Type().TerraformType(ctx)
	return r, tfsdk.Plan{Schema: s.Schema}, typ
}

func TestResourceCreateGeneratesThroughTheFramework(t *testing.T) {
	ctx := context.Background()
	r, plan, typ := resourceSchema(t)
	f := newFake()
	r.client = f
	plan.Raw = raw(typ, map[string]any{
		"id": tftypes.UnknownValue, "name": "db_pass", "generate": "words",
		"requires_consent": true, "modified": tftypes.UnknownValue, "expires_at": tftypes.UnknownValue,
	})
	resp := resource.CreateResponse{State: tfsdk.State{Schema: plan.Schema, Raw: tftypes.NewValue(typ, nil)}}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	var m secretResourceModel
	resp.State.Get(ctx, &m)
	if m.ID.ValueString() != "DB_PASS" || m.Name.ValueString() != "db_pass" || !m.Value.IsNull() {
		t.Fatalf("%+v", m)
	}
	if m.Modified.ValueString() != "2026-10-05 08:00" || !m.ExpiresAt.IsNull() {
		t.Fatalf("%+v", m)
	}
	if o := f.sets[0]; o.Generate != "words" || !o.RequiresConsent {
		t.Fatalf("%+v", o)
	}
}

func TestResourceStoreValueReadAndDelete(t *testing.T) {
	f := newFake()
	m := secretResourceModel{Name: types.StringValue("api"), Value: types.StringValue("v1"),
		TTLSecs: types.Int64Value(60), Generate: types.StringNull()}
	if err := storeSecret(f, &m); err != nil {
		t.Fatal(err)
	}
	if f.vals["API"] != "v1" || f.sets[0].TTLSecs != 60 || f.sets[0].Generate != "" {
		t.Fatalf("%v %+v", f.vals, f.sets)
	}
	if m.ExpiresAt.ValueString() != "2026-10-05 09:00" {
		t.Fatalf("%+v", m)
	}
	m.Value = types.StringValue("")
	if storeSecret(f, &m) == nil {
		t.Fatal("empty value accepted")
	}
	// Deleted outside Terraform: Read drops it from state.
	delete(f.infos, "API")
	if found, err := refreshMeta(f, &m); found || err != nil {
		t.Fatal("missing credential still found")
	}
	if err := deleteSecret(f, "API"); err != nil {
		t.Fatalf("already-gone delete: %v", err)
	}
	f.Set("B", "x", kepr.SetOptions{})
	if err := deleteSecret(f, "B"); err != nil || f.infos["B"] != nil {
		t.Fatal(err)
	}
}

func TestResourceValidateConfig(t *testing.T) {
	ctx := context.Background()
	r, plan, typ := resourceSchema(t)
	for _, tc := range []struct {
		set  map[string]any
		fail bool
	}{
		{map[string]any{"name": "A", "value": "v"}, false},
		{map[string]any{"name": "A"}, false},
		{map[string]any{"name": "A", "value": "v", "generate": "hex"}, true},
		{map[string]any{"name": "A", "value": ""}, true},
		{map[string]any{"name": "A", "ttl_secs": 0}, true},
	} {
		var resp resource.ValidateConfigResponse
		cfg := tfsdk.Config{Schema: plan.Schema, Raw: raw(typ, tc.set)}
		r.ValidateConfig(ctx, resource.ValidateConfigRequest{Config: cfg}, &resp)
		if resp.Diagnostics.HasError() != tc.fail {
			t.Fatalf("%v: %v", tc.set, resp.Diagnostics)
		}
	}
}

func readData(t *testing.T, f *fakeClient, name string) (secretDataModel, *datasource.ReadResponse) {
	ctx := context.Background()
	d := &secretDataSource{client: f}
	var s datasource.SchemaResponse
	d.Schema(ctx, datasource.SchemaRequest{}, &s)
	typ := s.Schema.Type().TerraformType(ctx)
	cfg := tfsdk.Config{Schema: s.Schema, Raw: raw(typ, map[string]any{"name": name})}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: s.Schema, Raw: tftypes.NewValue(typ, nil)}}
	d.Read(ctx, datasource.ReadRequest{Config: cfg}, resp)
	var m secretDataModel
	if !resp.Diagnostics.HasError() {
		resp.State.Get(ctx, &m)
	}
	return m, resp
}

func TestDataSourceReadsValuesAndRecordFields(t *testing.T) {
	f := newFake()
	f.Set("TOKEN", "t0k", kepr.SetOptions{TTLSecs: 5})
	f.Set("DB", `{"user":"app","password":"pw","port":5432}`, kepr.SetOptions{})
	f.infos["DB"].RecordType = "database"
	f.infos["DB"].Tags = []string{"prod"}

	m, resp := readData(t, f, "token")
	if resp.Diagnostics.HasError() || m.Value.ValueString() != "t0k" || !m.Fields.IsNull() ||
		m.ExpiresAt.ValueString() == "" || !m.Tags.IsNull() {
		t.Fatalf("%+v %v", m, resp.Diagnostics)
	}
	m, _ = readData(t, f, "DB")
	fields := map[string]string{}
	m.Fields.ElementsAs(context.Background(), &fields, false)
	if m.RecordType.ValueString() != "database" || fields["password"] != "pw" || fields["port"] != "5432" {
		t.Fatalf("%+v %v", m, fields)
	}
	if len(m.Tags.Elements()) != 1 {
		t.Fatalf("tags %v", m.Tags)
	}
}

func TestDataSourceRefusesSealedAndMissing(t *testing.T) {
	f := newFake()
	f.Set("AGENT", "sk-real", kepr.SetOptions{})
	f.infos["AGENT"].Sealed = true
	_, resp := readData(t, f, "agent")
	if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics[0].Detail(), "sealed") {
		t.Fatal(resp.Diagnostics)
	}
	for _, d := range resp.Diagnostics {
		if strings.Contains(d.Detail(), "sk-real") || strings.Contains(d.Summary(), "sk-real") {
			t.Fatal("value leaked into a diagnostic")
		}
	}
	if _, resp := readData(t, f, "NOPE"); !resp.Diagnostics.HasError() {
		t.Fatal("missing credential read")
	}
}

// TestLiveDaemon is the acceptance check: it needs a running kepr daemon.
func TestLiveDaemon(t *testing.T) {
	if os.Getenv("KEPR_TF_LIVE") == "" {
		t.Skip("set KEPR_TF_LIVE=1 with a running kepr daemon")
	}
	c := newDaemonClient("")
	name := "TF_LIVE_" + strconv.Itoa(os.Getpid())
	m := secretResourceModel{Name: types.StringValue(name), Generate: types.StringValue("hex")}
	if err := storeSecret(c, &m); err != nil {
		t.Fatal(err)
	}
	defer deleteSecret(c, name)
	dm := secretDataModel{Name: types.StringValue(name)}
	if d := readSecret(context.Background(), c, &dm); d.HasError() || len(dm.Value.ValueString()) == 0 {
		t.Fatal(d)
	}
}
