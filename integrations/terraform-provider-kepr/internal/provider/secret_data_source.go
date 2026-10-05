package provider

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSourceWithConfigure = (*secretDataSource)(nil)

// NewSecretDataSource is the kepr_secret data source.
func NewSecretDataSource() datasource.DataSource { return &secretDataSource{} }

type secretDataSource struct{ client Client }

type secretDataModel struct {
	Name       types.String `tfsdk:"name"`
	Value      types.String `tfsdk:"value"`
	Fields     types.Map    `tfsdk:"fields"`
	RecordType types.String `tfsdk:"record_type"`
	ExpiresAt  types.String `tfsdk:"expires_at"`
	Modified   types.String `tfsdk:"modified"`
	Tags       types.List   `tfsdk:"tags"`
}

func (d *secretDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (d *secretDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads one credential from kepr. The value is stored in Terraform state " +
			"(like any data source), so keep state encrypted. Sealed agent keys and SSH keys " +
			"are never returned.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required: true, Description: "Credential name (case-insensitive).",
				Validators: []validator.String{nameValidator{}},
			},
			"value": schema.StringAttribute{
				Computed: true, Sensitive: true, Description: "The stored value.",
			},
			"fields": schema.MapAttribute{
				Computed: true, Sensitive: true, ElementType: types.StringType,
				Description: "For a typed record (kepr record add), its fields.",
			},
			"record_type": schema.StringAttribute{Computed: true, Description: "Record type, if any."},
			"expires_at":  schema.StringAttribute{Computed: true, Description: "Expiry (UTC), if set with a TTL."},
			"modified":    schema.StringAttribute{Computed: true, Description: "Last change (UTC)."},
			"tags": schema.ListAttribute{
				Computed: true, ElementType: types.StringType, Description: "Tags, on daemons that support them.",
			},
		},
	}
}

func (d *secretDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	c, err := clientFrom(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Provider misconfigured", err.Error())
		return
	}
	if c != nil {
		d.client = c
	}
}

func (d *secretDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m secretDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(readSecret(ctx, d.client, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// readSecret fills m from the daemon: metadata first (so a sealed key gets
// a clear message without a refused Get), then the value.
func readSecret(ctx context.Context, c Client, m *secretDataModel) diag.Diagnostics {
	var diags diag.Diagnostics
	if c == nil {
		diags.AddError("Provider not configured", "the kepr provider has no daemon client")
		return diags
	}
	name := canonical(m.Name.ValueString())
	info, err := c.Info(name)
	if err != nil {
		diags.AddError("Cannot list kepr credentials", err.Error())
		return diags
	}
	if info == nil {
		diags.AddError("Credential not found", "kepr has no credential named "+name+".")
		return diags
	}
	if info.Sealed {
		diags.AddError("Sealed credential",
			name+" is write-only (sealed); kepr never returns its value. Use `kepr agent run` instead.")
		return diags
	}
	v, err := c.Get(name)
	if err != nil {
		diags.AddError("Cannot read "+name, err.Error())
		return diags
	}
	m.Value = types.StringValue(v)
	m.Fields = types.MapNull(types.StringType)
	m.RecordType = optString(info.RecordType)
	if info.RecordType != "" {
		fields, d := recordFields(ctx, v)
		diags.Append(d...)
		m.Fields = fields
	}
	m.ExpiresAt = optString(info.ExpiresAt)
	m.Modified = types.StringValue(info.Modified)
	tags, d := types.ListValueFrom(ctx, types.StringType, info.Tags)
	diags.Append(d...)
	if info.Tags == nil {
		tags = types.ListNull(types.StringType)
	}
	m.Tags = tags
	return diags
}

// recordFields turns a record's JSON object into a string map; non-string
// field values keep their JSON text.
func recordFields(ctx context.Context, v string) (types.Map, diag.Diagnostics) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(v), &raw); err != nil {
		return types.MapNull(types.StringType), nil
	}
	out := make(map[string]string, len(raw))
	for k, r := range raw {
		var s string
		if json.Unmarshal(r, &s) == nil {
			out[k] = s
		} else {
			out[k] = string(r)
		}
	}
	return types.MapValueFrom(ctx, types.StringType, out)
}

func optString(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}
