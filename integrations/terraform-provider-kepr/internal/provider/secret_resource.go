package provider

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	kepr "github.com/justdoGIT/kepr/sdk/go"
)

var (
	_ resource.ResourceWithConfigure      = (*secretResource)(nil)
	_ resource.ResourceWithImportState    = (*secretResource)(nil)
	_ resource.ResourceWithValidateConfig = (*secretResource)(nil)
)

// NewSecretResource is the kepr_secret resource.
func NewSecretResource() resource.Resource { return &secretResource{} }

type secretResource struct{ client Client }

type secretResourceModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Value           types.String `tfsdk:"value"`
	Generate        types.String `tfsdk:"generate"`
	TTLSecs         types.Int64  `tfsdk:"ttl_secs"`
	RequiresConsent types.Bool   `tfsdk:"requires_consent"`
	Modified        types.String `tfsdk:"modified"`
	ExpiresAt       types.String `tfsdk:"expires_at"`
}

func (r *secretResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *secretResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		Description: "A credential in kepr. With `generate`, the daemon creates the value and it " +
			"never enters Terraform state; read it where needed with `kepr exec` or the data source.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, Description: "The credential name as the daemon stores it (upper case).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required: true, Description: "Credential name (case-insensitive).",
				Validators: []validator.String{nameValidator{}}, PlanModifiers: replace,
			},
			"value": schema.StringAttribute{
				Optional: true, Sensitive: true,
				Description: "Value to store. Omit it to have kepr generate one (see `generate`).",
			},
			"generate": schema.StringAttribute{
				Optional: true, Description: "Generated value kind when `value` is omitted (default hex).",
				Validators: []validator.String{kindValidator{}}, PlanModifiers: replace,
			},
			"ttl_secs": schema.Int64Attribute{
				Optional: true, Description: "Expire the credential this many seconds after it is set.",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"requires_consent": schema.BoolAttribute{
				Optional: true, Description: "Every read needs a desktop consent prompt.",
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()},
			},
			"modified":   schema.StringAttribute{Computed: true, Description: "Last change (UTC)."},
			"expires_at": schema.StringAttribute{Computed: true, Description: "Expiry (UTC), if `ttl_secs` is set."},
		},
	}
}

func (r *secretResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	c, err := clientFrom(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Provider misconfigured", err.Error())
		return
	}
	if c != nil {
		r.client = c
	}
}

type attrValue interface {
	IsNull() bool
	IsUnknown() bool
}

// known: set in config/plan and not computed later.
func known(v attrValue) bool { return !v.IsNull() && !v.IsUnknown() }

func (r *secretResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m secretResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if known(m.Value) && known(m.Generate) {
		resp.Diagnostics.AddAttributeError(path.Root("generate"), "Conflicting attributes",
			"Set `value` or `generate`, not both.")
	}
	if known(m.Value) && m.Value.ValueString() == "" {
		resp.Diagnostics.AddAttributeError(path.Root("value"), "Empty value",
			"Omit `value` to generate one instead of storing an empty string.")
	}
	if known(m.TTLSecs) && m.TTLSecs.ValueInt64() <= 0 {
		resp.Diagnostics.AddAttributeError(path.Root("ttl_secs"), "Invalid TTL", "ttl_secs must be positive.")
	}
}

// storeSecret writes m to the daemon (Create and value updates).
func storeSecret(c Client, m *secretResourceModel) error {
	if c == nil {
		return errors.New("the kepr provider has no daemon client")
	}
	name := canonical(m.Name.ValueString())
	o := kepr.SetOptions{RequiresConsent: m.RequiresConsent.ValueBool()}
	if known(m.TTLSecs) {
		o.TTLSecs = uint64(m.TTLSecs.ValueInt64())
	}
	value := ""
	if known(m.Value) {
		value = m.Value.ValueString()
		if value == "" {
			return errors.New("value must not be empty")
		}
	} else {
		o.Generate = m.Generate.ValueString()
		if o.Generate == "" {
			o.Generate = "hex"
		}
	}
	if err := c.Set(name, value, o); err != nil {
		return err
	}
	m.ID = types.StringValue(name)
	_, err := refreshMeta(c, m)
	return err
}

// refreshMeta copies the daemon's metadata into m; false when the
// credential no longer exists.
func refreshMeta(c Client, m *secretResourceModel) (bool, error) {
	if c == nil {
		return false, errors.New("the kepr provider has no daemon client")
	}
	info, err := c.Info(m.ID.ValueString())
	if err != nil || info == nil {
		return false, err
	}
	if m.Name.IsNull() {
		m.Name = types.StringValue(info.Name) // after import
	}
	m.Modified = types.StringValue(info.Modified)
	m.ExpiresAt = optString(info.ExpiresAt)
	return true, nil
}

func (r *secretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m secretResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := storeSecret(r.client, &m); err != nil {
		resp.Diagnostics.AddError("Cannot store "+canonical(m.Name.ValueString()), err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *secretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m secretResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	found, err := refreshMeta(r.client, &m)
	if err != nil {
		resp.Diagnostics.AddError("Cannot list kepr credentials", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx) // deleted or expired outside Terraform
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// Update runs only for a changed `value`; every other input forces replacement.
func (r *secretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m secretResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := storeSecret(r.client, &m); err != nil {
		resp.Diagnostics.AddError("Cannot update "+canonical(m.Name.ValueString()), err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *secretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m secretResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := deleteSecret(r.client, m.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Cannot delete "+m.ID.ValueString(), err.Error())
	}
}

// deleteSecret treats "already gone" as success.
func deleteSecret(c Client, id string) error {
	if c == nil {
		return errors.New("the kepr provider has no daemon client")
	}
	err := c.Delete(id)
	if err == nil {
		return nil
	}
	if info, ierr := c.Info(id); ierr == nil && info == nil {
		return nil
	}
	return err
}

func (r *secretResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), canonical(req.ID))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}
