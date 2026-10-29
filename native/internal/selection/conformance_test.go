package selection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestTypeScriptConformance(t *testing.T) {
	data, e := os.ReadFile("../../../packages/modules/fixtures/planner.json")
	if e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != oracleCorpusSHA256 {
		t.Fatal("fixture digest drift; regenerate from TypeScript oracle")
	}
	var corpus struct {
		ExistingTests int `json:"existingTests"`
		Cases         []struct {
			Name     string          `json:"name"`
			Input    json.RawMessage `json:"input"`
			Expected json.RawMessage `json:"expected"`
		} `json:"cases"`
	}
	if e = json.Unmarshal(data, &corpus); e != nil {
		t.Fatal(e)
	}
	if corpus.ExistingTests != 30 || len(corpus.Cases) < 280 {
		t.Fatal("incomplete corpus")
	}
	for _, c := range corpus.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var got, want any
			if e := json.Unmarshal(Outcome(c.Input), &got); e != nil {
				t.Fatal(e)
			}
			if e := json.Unmarshal(c.Expected, &want); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("input %s\ngot %s\nwant %s", c.Input, Outcome(c.Input), c.Expected)
			}
		})
	}
}
