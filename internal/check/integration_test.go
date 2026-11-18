package check

import (
	"bytes"
	"crypto/sha256"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/vincent119/tlscheck/internal/input"
	"github.com/vincent119/tlscheck/internal/model"
)

func TestParsedPEMAndDERIntegrateWithoutChangingFiles(t *testing.T) {
	root, ca, leaf := chain(t)
	directory := t.TempDir()
	rootPath := filepath.Join(directory, "root.data")
	bundlePath := filepath.Join(directory, "bundle.data")
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Cert.Raw})
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})...)
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Cert.Raw})...)
	files := map[string][]byte{rootPath: root.Cert.Raw, bundlePath: bundle}
	for path, data := range files {
		if err := os.WriteFile(path, data, 0400); err != nil {
			t.Fatal(err)
		}
	}
	var certificates []model.ParsedCertificate
	for _, result := range input.NewParser().ParseAll(t.Context(), []string{bundlePath, rootPath}) {
		if len(result.Issues) != 0 {
			t.Fatalf("解析失敗：%v", result.Issues)
		}
		certificates = append(certificates, result.Certificates...)
	}
	result := NewAnalyzer(fixedNow(), rootsProvider(root.Cert)).AnalyzeLocal(t.Context(), certificates)
	if result.Failure() != NoFailure || len(result.Certificates) != 3 {
		t.Fatalf("PEM／DER 整合錯誤：%+v", result)
	}
	leafResult := findResult(t, result, leaf.Cert)
	if len(leafResult.Sources) != 2 || leafResult.Sources[0].Block != 1 || leafResult.Sources[1].Block != 3 || leafResult.Sources[0].Path != bundlePath {
		t.Fatal("PEM 位置或去重來源遺失")
	}
	rootResult := findResult(t, result, root.Cert)
	if rootResult.Sources[0].Encoding != "DER" || rootResult.Sources[0].Block != 0 {
		t.Fatal("DER 來源錯誤")
	}
	for path, before := range files {
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) || sha256.Sum256(before) != sha256.Sum256(after) {
			t.Fatal("原檔遭修改")
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 2 {
		t.Fatal("產生未要求的鄰近檔案")
	}
}
