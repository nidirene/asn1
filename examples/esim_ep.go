package esim

import "github.com/nidirene/asn1"

var ValMaxUInt8 int64 = 255

type UInt8 = int

var ValMaxUInt15 int64 = 32767

type UInt15 = int

var ValMaxUInt16 int = 65535

type UInt16 = int

var ValMaxUInt31 int = 2147483647

type (
	UInt31                = int
	ApplicationIdentifier = []byte
	PEHeader              struct {
		Mandated       asn1.Null `asn1:"optional"`
		Identification UInt15
	}
)

type ProfileElement = interface{}

type ProfileHeader struct {
	Major_version             UInt8        `asn1:"tag:0"`
	Minor_version             UInt8        `asn1:"tag:1"`
	ProfileType               string       `asn1:"optional,tag:2"`
	Iccid                     []byte       `asn1:"tag:3"`
	Pol                       []byte       `asn1:"optional,tag:4"`
	EUICC_Mandatory_services  ServicesList `asn1:"tag:5"`
	EUICC_Mandatory_GFSTEList []asn1.Oid   `asn1:"tag:6"`
	ConnectivityParameters    []byte       `asn1:"optional,tag:7"`
	EUICC_Mandatory_AIDs      []struct {
		Aid     ApplicationIdentifier
		Version []byte
	} `asn1:"optional,tag:8"`
	IotOptions IotOptions `asn1:"optional,tag:9"`
}
type IotOptions struct {
	Pix []byte
}
type ServicesList struct {
	Contactless                    asn1.Null `asn1:"optional,tag:0"`
	Usim                           asn1.Null `asn1:"optional,tag:1"`
	Isim                           asn1.Null `asn1:"optional,tag:2"`
	Csim                           asn1.Null `asn1:"optional,tag:3"`
	Milenage                       asn1.Null `asn1:"optional,tag:4"`
	Tuak128                        asn1.Null `asn1:"optional,tag:5"`
	Cave                           asn1.Null `asn1:"optional,tag:6"`
	Gba_usim                       asn1.Null `asn1:"optional,tag:7"`
	Gba_isim                       asn1.Null `asn1:"optional,tag:8"`
	Mbms                           asn1.Null `asn1:"optional,tag:9"`
	Eap                            asn1.Null `asn1:"optional,tag:10"`
	Javacard                       asn1.Null `asn1:"optional,tag:11"`
	Multos                         asn1.Null `asn1:"optional,tag:12"`
	Multiple_usim                  asn1.Null `asn1:"optional,tag:13"`
	Multiple_isim                  asn1.Null `asn1:"optional,tag:14"`
	Multiple_csim                  asn1.Null `asn1:"optional,tag:15"`
	Tuak256                        asn1.Null `asn1:"optional,tag:16"`
	Usim_test_algorithm            asn1.Null `asn1:"optional,tag:17"`
	Ber_tlv                        asn1.Null `asn1:"optional,tag:18"`
	DfLink                         asn1.Null `asn1:"optional,tag:19"`
	Cat_tp                         asn1.Null `asn1:"optional,tag:20"`
	Get_identity                   asn1.Null `asn1:"optional,tag:21"`
	Profile_a_x25519               asn1.Null `asn1:"optional,tag:22"`
	Profile_b_p256                 asn1.Null `asn1:"optional,tag:23"`
	SuciCalculatorApi              asn1.Null `asn1:"optional,tag:24"`
	Dns_resolution                 asn1.Null `asn1:"optional,tag:25"`
	Scp11ac                        asn1.Null `asn1:"optional,tag:26"`
	Scp11c_authorization_mechanism asn1.Null `asn1:"optional,tag:27"`
	S16mode                        asn1.Null `asn1:"optional,tag:28"`
	Eaka                           asn1.Null `asn1:"optional,tag:29"`
}
type PE_GenericFileManagement struct {
	Gfm_header PEHeader
	// FileManagementCMD []FileManagement
}

// type (
//
//	FileManagement   = []asn1.RawValue
//	MappingParameter struct {
//		MappingOptions []byte
//		MappingSource  ApplicationIdentifier
//	}
//
// )
type (
	UICCCapability  = asn1.BitString
	ProprietaryInfo struct {
		SpecialFileInformation []byte `asn1:"optional,private,tag:0"`
	}
)
