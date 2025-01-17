package sops

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var testAccProviders map[string]*schema.Provider
var testAccProvider *schema.Provider

func init() {
	testAccProvider = New("")()
	testAccProviders = map[string]*schema.Provider{
		"sops": testAccProvider,
	}
}

func TestProvider(t *testing.T) {
	if err := New("")().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_impl(t *testing.T) {
	var _ *schema.Provider = New("")()
}
