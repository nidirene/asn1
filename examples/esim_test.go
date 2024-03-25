package esim

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/nidirene/asn1"
)

type testCase struct {
	value    interface{} // should be pointer
	expected []byte      // should be value
}

func ParseDerTlvHex(str string) []byte {
	buf := bytes.NewBuffer([]byte{})
	for _, line := range strings.Split(str, "\n") {
		elem := strings.ReplaceAll(strings.TrimSpace(line), " ", "")
		x, err := hex.DecodeString(elem)
		if err != nil {
			panic(err)
		}
		buf.Write(x)
	}
	return buf.Bytes()
}

// isBytesEqual compares two byte arrays/slices.
func isBytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (t testCase) String() string {
	return fmt.Sprintf("testCase: value %#v (%T) expects %#v", t.value, t.value, t.expected)
}

// testEncode encodes an object and compares with the expected bytes.
func testEncode(t *testing.T, ctx *asn1.Context, options string, tests ...testCase) {
	for _, test := range tests {
		t.Logf("Testing case: %v", test)
		data, err := ctx.EncodeWithOptions(test.value, options)
		if err != nil {
			t.Fatal(err)
		}
		if !isBytesEqual(data, test.expected) {
			t.Fatalf("Failed to encode \"%v\".\n Expected: %#v.\n Got:      %#v",
				test.value, test.expected, data)
		}
	}
}

func checkEqual(t *testing.T, obj1 interface{}, obj2 interface{}) {
	equal := false
	switch val1 := obj1.(type) {
	case *big.Int:
		val2, ok := obj2.(*big.Int)
		equal = ok && val1.Cmp(val2) == 0
	default:
		equal = reflect.DeepEqual(obj1, obj2)
	}
	if !equal {
		t.Fatalf("Decoded value does not match.\n Got \"%v\" (%T)\n When decoding \"%v\" (%T)",
			obj1, obj1, obj2, obj2)
	}
}

// testDecode decodes a sequence of bytes and compares with the target object.
func testDecode(t *testing.T, ctx *asn1.Context, options string, tests ...testCase) {
	for _, test := range tests {
		value := reflect.New(reflect.TypeOf(test.value))
		rest, err := ctx.DecodeWithOptions(test.expected, value.Interface(), options)
		if err != nil {
			t.Fatal(err)
		}
		if len(rest) > 0 {
			t.Fatalf("Unexpected remaining bytes when decoding \"%v\": %#v\n",
				test.value, rest)
		}
		checkEqual(t, value.Elem().Interface(), test.value)
	}
}

// testEncodeDecode does testEncode and testDecode.
func testEncodeDecode(t *testing.T, ctx *asn1.Context, options string, tests ...testCase) {
	for _, test := range tests {
		testEncode(t, ctx, options, test)
		testDecode(t, ctx, options, test)
	}
}

func TestServicesList(t *testing.T) {
	ctx := asn1.NewContext()
	// Use BER for encodeing and  decoding
	ctx.SetDer(true, true)
	present := asn1.Null{Present: true}

	msgBytes := ParseDerTlvHex(`
A5 06 
  81 00 
  84 00 
  8B 00 
`)
	bs := ServicesList{
		Usim:     present,
		Milenage: present,
		Javacard: present,
	}
	testEncode(t, ctx, "tag:5", testCase{value: bs, expected: msgBytes})
	testDecode(t, ctx, "tag:5", testCase{value: bs, expected: msgBytes})
}

func TestProfileHeader(t *testing.T) {
	ctx := asn1.NewContext()
	// Use BER for encodeing and  decoding
	ctx.SetDer(false, false)

	present := asn1.Null{Present: true}
	msgBytes := ParseDerTlvHex(`
A0 41 
  80 01 03 
  81 01 00 
  82 12 5443412053616D706C652050726F66696C65 
  83 0A 89019990001234567893 
  A5 06 
    81 00 
    84 00 
    8B 00 
  A6 11 
    06 06 67810F010201 
    06 07 67810F01020402
`)

	bs := ProfileHeader{
		Major_version: 3,
		Minor_version: 0,
		ProfileType:   "TCA Sample Profile",
		Iccid:         []byte{0x89, 0x01, 0x99, 0x90, 0x00, 0x12, 0x34, 0x56, 0x78, 0x93},
		EUICC_Mandatory_services: ServicesList{
			Usim:     present,
			Milenage: present,
			Javacard: present,
		},
		EUICC_Mandatory_GFSTEList: []asn1.Oid{
			[]uint{2, 23, 143, 1, 2, 1},
			[]uint{2, 23, 143, 1, 2, 4, 2},
		},
	}

	testEncode(t, ctx, "tag:0", testCase{value: bs, expected: msgBytes})
	testDecode(t, ctx, "tag:0", testCase{value: bs, expected: msgBytes})
}

func TestSimpleOid(t *testing.T) {
	// Cases that encoding and decoding do not match
	tests := []testCase{
		{asn1.Oid{2, 23, 143, 1, 2, 1}, []byte{0x06, 0x06, 0x67, 0x81, 0x0F, 0x01, 0x02, 0x01}},
		{asn1.Oid{2, 23, 143, 1, 2, 4, 2}, []byte{0x06, 0x07, 0x67, 0x81, 0x0F, 0x01, 0x02, 0x04, 0x02}},
	}
	t.Logf(">> %v", []byte{byte(2*40 + 23)})
	ctx := asn1.NewContext()
	ctx.SetDer(true, true)
	testEncode(t, ctx, "", tests...)
}
