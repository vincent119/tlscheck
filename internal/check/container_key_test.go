package check

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"

	"github.com/vincent119/tlscheck/internal/testutil"
)

func TestPKCS12KeysKeepExistingValidityChecks(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []crypto.Signer{rsaKey, ecKey, testutil.NewKey(t)} {
		before := AnalyzeKey(t.Context(), keyInput(key, "PKCS#8", 0))
		after := AnalyzeKey(t.Context(), keyInput(key, "PKCS#12", 0))
		if before.Validation.Status != Passed || after.Validation != before.Validation || !reflect.DeepEqual(before.Checks, after.Checks) || after.Info.Format != "PKCS#12" {
			t.Fatal("PFX格式改變既有有效性檢查")
		}
	}
}
