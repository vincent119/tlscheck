package check

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"reflect"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/testutil"
)

func TestCompareCertificateMatchesObservedLeaf(t *testing.T) {
	root, ca, leaf := remoteIdentity(t, nil)
	target, observed := remoteServer(t, remoteTLSConfig(leaf, ca))
	checker := checkerForLocalServer(root.Cert)
	original := checker.Check(t.Context(), target)
	r := original.WithCertificateComparison("candidate.pem", leaf.Cert)
	if r.Failure() != NoFailure || r.Comparison.Outcome.Status != Passed || len(r.Comparison.Differences) != 0 || r.Comparison.CandidateFingerprintSHA256 != r.Comparison.ObservedFingerprintSHA256 || original.Comparison != nil {
		t.Fatal("同憑證比對不符或改寫來源")
	}
	state := <-observed
	if state.applicationBytes != 0 {
		t.Fatal("比對不得傳送應用資料")
	}
}

func TestCompareCertificateRejectsSameKeyRenewal(t *testing.T) {
	template := testutil.Template(100, "same-key", fixedNow(), false)
	first := testutil.Issue(t, template, nil, nil)
	template.SerialNumber.SetInt64(101)
	template.NotAfter = template.NotAfter.Add(24 * time.Hour)
	second := testutil.Issue(t, template, nil, first.Key)
	if !bytes.Equal(first.Cert.RawSubjectPublicKeyInfo, second.Cert.RawSubjectPublicKeyInfo) {
		t.Fatal("續期前置條件不符")
	}
	r := RemoteResult{ServerChain: []*x509.Certificate{second.Cert}}.WithCertificateComparison("first.pem", first.Cert)
	fields := []string{}
	for _, d := range r.Comparison.Differences {
		fields = append(fields, d.Field)
	}
	if r.Failure() != VerificationFailure || !reflect.DeepEqual(fields, []string{"serial_number", "not_after"}) {
		t.Fatal("同公鑰續期誤判一致或差異順序不符", fields)
	}
}

func TestCertificateMatchDoesNotGrantTrust(t *testing.T) {
	root, ca, leaf := remoteIdentity(t, nil)
	target, observed := remoteServer(t, remoteTLSConfig(leaf, ca))
	target.Host = "wrong.test"
	target.ASCIIHost = "wrong.test"
	r := checkerForLocalServer(root.Cert).Check(t.Context(), target).WithCertificateComparison("same.pem", leaf.Cert)
	if r.Comparison.Outcome.Status != Passed || r.Trust.Hostname.Status != Failed || r.Failure() != VerificationFailure {
		t.Fatal("匹配提升了名稱信任")
	}
	<-observed
	target2, observed2 := remoteServer(t, remoteTLSConfig(leaf, ca))
	other := testutil.Issue(t, testutil.Template(200, "unrelated-root", fixedNow(), true), nil, nil)
	r = checkerForLocalServer(other.Cert).Check(t.Context(), target2).WithCertificateComparison("same.pem", leaf.Cert)
	if r.Comparison.Outcome.Status != Passed || r.Trust.Outcome.Status != Failed || r.Failure() != VerificationFailure {
		t.Fatal("候選被加入信任根")
	}
	<-observed2
}

func TestCompareCertificateKeepsMissingLeafAndOtherDERChanges(t *testing.T) {
	template := testutil.Template(22, "leaf", fixedNow(), false)
	leaf := testutil.Issue(t, template, nil, nil)
	original := RemoteResult{Issues: []Outcome{failed("remote.connect_failed", ExecutionFailure)}}
	r := original.WithCertificateComparison("leaf.pem", leaf.Cert)
	if r.Comparison.Outcome.Status != NotPerformed || r.Comparison.ObservedFingerprintSHA256 != "" || r.Failure() != ExecutionFailure {
		t.Fatal("未觀測leaf仍宣稱比對")
	}
	template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
	other := testutil.Issue(t, template, nil, leaf.Key)
	r = RemoteResult{ServerChain: []*x509.Certificate{other.Cert}}.WithCertificateComparison("leaf.pem", leaf.Cert)
	if r.Failure() != VerificationFailure || len(r.Comparison.Differences) != 1 || r.Comparison.Differences[0].Field != "certificate_der" {
		t.Fatal("其他DER差異遭忽略")
	}
}

func TestCompareCertificateSortsSetsWithoutMutatingCertificate(t *testing.T) {
	leaf := testutil.Issue(t, testutil.Template(24, "leaf", fixedNow(), false), nil, nil)
	candidate := *leaf.Cert
	observed := *leaf.Cert
	candidate.DNSNames = []string{"z.test", "a.test", "a.test"}
	observed.DNSNames = []string{"b.test"}
	observed.Raw = append(bytes.Clone(observed.Raw), 0)
	r := RemoteResult{ServerChain: []*x509.Certificate{&observed}}.WithCertificateComparison("leaf.pem", &candidate)
	diff := r.Comparison.Differences[0]
	if diff.Field != "dns_names" || !reflect.DeepEqual(diff.Candidate, []string{"a.test", "z.test"}) || !reflect.DeepEqual(candidate.DNSNames, []string{"z.test", "a.test", "a.test"}) {
		t.Fatal("集合順序不符或修改憑證")
	}
}
