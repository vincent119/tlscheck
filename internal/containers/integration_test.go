package containers

import (
	"context"
	"github.com/vincent119/tlscheck/internal/testutil"
	"testing"
)

func TestProductContainerFixture(t *testing.T) {
	data := testutil.ContainerFixture(t, "modern.pfx")
	result, err := Decode(context.Background(), data, []byte("S12_SYNTHETIC_PASSWORD_CANARY"))
	if err != nil || len(result.Certificates()) != 2 || result.Signer() == nil {
		t.Fatal("產品解碼契約失敗", err)
	}
}
