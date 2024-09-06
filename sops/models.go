package sops

type EncryptConfig struct {
	Kms KmsConf
	Age string
}
type KmsConf struct {
	ARN     string
	Profile string
}

func (c *KmsConf) IsConfigured() bool {
	return len(c.ARN) > 0 && len(c.Profile) > 0
}
