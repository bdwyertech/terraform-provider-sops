package sops

import (
	scommon "github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/config"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func GetInputStore(d *schema.ResourceData) scommon.Store {
	return scommon.DefaultStoreForPathOrFormat(config.NewStoresConfig(), d.Get("filename").(string), "file")
}
func GetOutputStore(d *schema.ResourceData) scommon.Store {
	return scommon.DefaultStoreForPathOrFormat(config.NewStoresConfig(), d.Get("filename").(string), "file")
}
