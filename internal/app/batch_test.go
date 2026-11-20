package app

import "testing"

func TestBatchFlagsPreserveCLIPlaceholderOrder(t *testing.T) {
	o, err := parseOptions([]string{"first.invalid", "--targets-file", "one.txt", "--local", "cert.pem", "--targets-file=two.txt", "--concurrency", "2"})
	if err != nil {
		t.Fatal("批次旗標未支援", err)
	}
	want := []string{"first.invalid", "one.txt", "cert.pem", "two.txt"}
	if len(o.Inputs) != len(want) {
		t.Fatal("CLI展開佔位順序不符", len(o.Inputs))
	}
	for i, value := range want {
		if o.Inputs[i].Value != value || o.Inputs[i].Index != i {
			t.Fatal("輸入順序錯誤", i)
		}
	}
}
