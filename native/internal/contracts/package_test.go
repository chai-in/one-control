package contracts

import "testing"

func TestPackageAttestationStrictWire(t *testing.T) {
	raw := []byte(`{"schemaVersion":1,"id":"shared.payload","version":"1.0.0","platform":"win-x64","publisher":"fixture.publisher","layout":"passive-v1","archiveSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","archiveSize":123,"files":[{"path":"data/payload.txt","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":7}],"issuedAt":100,"expiresAt":200}`)
	var p PackageAttestation
	if _, e := Decode(raw, "PackageAttestation", &p); e != nil {
		t.Fatal(e)
	}
	if p.Publisher != "fixture.publisher" || len(p.Files) != 1 {
		t.Fatal("wire values")
	}
	if _, e := Decode(raw, "Manifest", &Manifest{}); e == nil {
		t.Fatal("manifest widened")
	}
}
