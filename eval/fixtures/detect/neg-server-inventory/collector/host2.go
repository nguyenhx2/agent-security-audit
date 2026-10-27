package collector

type Host2 struct {
	FirmwareVersion string `json:"firmware_version"`
	SecureBoot bool `json:"secure_boot"`
	BiosVendor string
}
