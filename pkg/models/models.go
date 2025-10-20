package models

type ChainElement struct {
	Cert string `json:"cert" yaml:"cert" validate:"required"`
	Name string `json:"name" yaml:"name"`
	Key  string `json:"key" yaml:"key"`
}

type ClientSSLProfile struct {
	Name         string         `json:"name" yaml:"name" validate:"required"`
	Partition    string         `json:"partition" yaml:"partition" validate:"required"`
	Cert         string         `json:"cert" yaml:"cert"`
	Key          string         `json:"key" yaml:"key"`
	CertKeyChain []ChainElement `json:"certKeyChain" yaml:"cert_key_chain"`
	CipherGroup  string         `json:"cipherGroup" yaml:"cipher_group"`
	Ciphers      string         `json:"ciphers" yaml:"ciphers"`
	DefaultsFrom string         `json:"defaultsFrom" yaml:"defaults_from"`
	SelfLink     string         `json:"selfLink"`
}

type CipherGroup struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}
