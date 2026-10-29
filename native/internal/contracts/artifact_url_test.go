package contracts

import (
	"encoding/json"
	"os"
	"testing"
)

func TestArtifactURLContract(t *testing.T) {
	data, err := os.ReadFile("../../../packages/module-contracts/tests/artifact-urls.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases map[string][]string
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for group, urls := range cases {
		for _, value := range urls {
			t.Run(value, func(t *testing.T) {
				raw, _ := json.Marshal(Artifact{URL: value, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Size: 1})
				var artifact Artifact
				_, err := Decode(raw, "Artifact", &artifact)
				if (err == nil) != (group == "accepted") {
					t.Fatalf("group %s, error %v", group, err)
				}
			})
		}
	}
}
