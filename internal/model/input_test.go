package model

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestPrivateKeyFormattingDoesNotRevealMaterial(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parsed := NewParsedKey(SourceRef{Path: "local/test.key"}, "PKCS#8", key)
	if parsed.Signer() == nil {
		t.Fatal("記憶體內金鑰遺失")
	}
	encoded, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{string(encoded), fmt.Sprintf("%v", parsed), fmt.Sprintf("%+v", parsed), fmt.Sprintf("%#v", parsed)} {
		if strings.Contains(output, "signer") || strings.Contains(output, fmt.Sprint([]byte(key))) {
			t.Fatalf("輸出含私密內容：%s", output)
		}
	}
}
