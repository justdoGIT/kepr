package provider

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	kepr "github.com/justdoGIT/kepr/sdk/go"
)

// Client is the part of the kepr Go SDK the provider uses; tests use a fake.
type Client interface {
	Get(name string) (string, error)
	Set(name, value string, o kepr.SetOptions) error
	Delete(name string) error
	Info(name string) (*kepr.CredInfo, error)
}

func newDaemonClient(socketPath string) Client {
	c := kepr.New()
	if socketPath != "" {
		c.Path = socketPath
	}
	return c
}

// clientFrom unwraps the provider's configured client.
func clientFrom(data any) (Client, error) {
	if data == nil {
		return nil, nil
	}
	c, ok := data.(Client)
	if !ok {
		return nil, fmt.Errorf("unexpected provider data %T", data)
	}
	return c, nil
}

// canonical is the daemon's form of a credential name.
func canonical(name string) string { return strings.ToUpper(name) }

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)

// nameValidator mirrors the daemon's name rule (it validates again).
type nameValidator struct{}

func (nameValidator) Description(context.Context) string {
	return "letters, digits and underscores, at most 128 characters"
}

func (v nameValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v nameValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if !nameRe.MatchString(req.ConfigValue.ValueString()) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid credential name",
			"A kepr credential name uses "+v.Description(ctx)+".")
	}
}

// kindValidator accepts the daemon's generate kinds.
type kindValidator struct{}

func (kindValidator) Description(context.Context) string {
	return "one of " + strings.Join(kepr.GenerateKinds, ", ")
}

func (v kindValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v kindValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if !slices.Contains(kepr.GenerateKinds, req.ConfigValue.ValueString()) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid generate kind", "Use "+v.Description(ctx)+".")
	}
}
