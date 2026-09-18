package model

// AzureRegions is the list of Azure public region names accepted for `region` attributes
// (docs/02 §4). GenericRegions cover non-Azure providers.
var AzureRegions = map[string]struct{}{
	"switzerlandnorth": {}, "switzerlandwest": {}, "westeurope": {}, "northeurope": {}, "germanywestcentral": {},
	"germanynorth": {}, "francecentral": {}, "francesouth": {}, "uksouth": {}, "ukwest": {}, "swedencentral": {},
	"swedensouth": {}, "norwayeast": {}, "norwaywest": {}, "italynorth": {}, "polandcentral": {}, "spaincentral": {},
	"austriaeast": {}, "belgiumcentral": {}, "denmarkeast": {}, "eastus": {}, "eastus2": {}, "centralus": {},
	"northcentralus": {}, "southcentralus": {}, "westcentralus": {}, "westus": {}, "westus2": {}, "westus3": {},
	"canadacentral": {}, "canadaeast": {}, "brazilsouth": {}, "brazilsoutheast": {}, "mexicocentral": {},
	"chilecentral": {}, "australiaeast": {}, "australiasoutheast": {}, "australiacentral": {}, "australiacentral2": {},
	"japaneast": {}, "japanwest": {}, "koreacentral": {}, "koreasouth": {}, "southeastasia": {}, "eastasia": {},
	"centralindia": {}, "southindia": {}, "westindia": {}, "jioindiawest": {}, "jioindiacentral": {},
	"indonesiacentral": {}, "malaysiawest": {}, "newzealandnorth": {}, "taiwannorth": {}, "uaenorth": {},
	"uaecentral": {}, "qatarcentral": {}, "israelcentral": {}, "southafricanorth": {}, "southafricawest": {},
}

// GenericRegions are provider-agnostic codes (LLM providers, SaaS).
var GenericRegions = map[string]struct{}{
	"": {}, "unknown": {}, "global": {}, "eu": {}, "us": {}, "ch": {}, "uk": {}, "apac": {}, "on-prem": {},
}

// ValidRegion reports whether a region code is acceptable.
func ValidRegion(r string) bool {
	if _, ok := AzureRegions[r]; ok {
		return true
	}
	_, ok := GenericRegions[r]
	return ok
}
