package sops

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func New(version string) func() *schema.Provider {
	return func() *schema.Provider {
		return &schema.Provider{
			ConfigureContextFunc: ConfigureProvider,
			DataSourcesMap: map[string]*schema.Resource{
				"sops_file":       dataSourceFile(),
				"sops_file_entry": dataSourceFileKey(),
				"sops_external":   dataSourceExternal(),
			},
			ResourcesMap: map[string]*schema.Resource{
				"sops_file": resourceSourceFile(),
			},
			Schema: map[string]*schema.Schema{
				"kms": {
					Type:        schema.TypeMap,
					Optional:    true,
					Description: providerDescriptions["kms"],
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},
				"age": {
					Type:        schema.TypeMap,
					Optional:    true,
					Description: providerDescriptions["age"],
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},
			},
		}
	}
}

var providerDescriptions = map[string]string{
	"kms": "Configuration for encrypt files with AWS KMS.",
	"age": "Configuration for encrypt files with Age.",
}

func ConfigureProvider(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics
	encConf := &EncryptConfig{}
	kms, err := GetKmsConf(d)
	if err != nil {
		fmt.Println("failed to init kms")
	} else {
		encConf.Kms = kms
	}
	age, err := GetAgeConf(d)
	if err != nil {
		fmt.Println("failed to init age")
	} else {
		encConf.Age = age
	}

	return encConf, diags
}
