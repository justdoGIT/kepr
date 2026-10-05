// Package provider implements the kepr Terraform provider: a kepr_secret
// data source and resource backed by the local kepr daemon socket.
package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = (*keprProvider)(nil)

type keprProvider struct {
	version string
	// newClient builds the daemon client; tests swap in a fake.
	newClient func(socketPath string) Client
}

type providerModel struct {
	SocketPath types.String `tfsdk:"socket_path"`
}

// New returns the provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &keprProvider{version: version, newClient: newDaemonClient}
	}
}

func (p *keprProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "kepr"
	resp.Version = p.version
}

func (p *keprProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads and writes credentials in the local kepr daemon. " +
			"Terraform runs as the calling user; the daemon applies its own rules " +
			"(per-user namespace, audit, consent prompts, sealed credentials never returned).",
		Attributes: map[string]schema.Attribute{
			"socket_path": schema.StringAttribute{
				Optional: true,
				Description: "Daemon socket. Default: $XDG_RUNTIME_DIR/kepr/kepr.sock, " +
					"or /run/kepr/kepr.sock with KEPR_SYSTEM_MODE=1.",
			},
		},
	}
}

func (p *keprProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var m providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	c := p.newClient(m.SocketPath.ValueString())
	resp.DataSourceData = c
	resp.ResourceData = c
}

func (p *keprProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{NewSecretResource}
}

func (p *keprProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{NewSecretDataSource}
}
