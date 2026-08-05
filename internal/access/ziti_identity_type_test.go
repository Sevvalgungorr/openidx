package access

import (
	"encoding/json"
	"testing"
)

// TestZitiIdentityTypeUnmarshal locks in tolerance for both shapes OpenZiti has
// used for an identity's "type": a bare string on older controllers and an
// entity-reference object ({id,name}) on newer ones. The object form previously
// failed the whole identity list decode ("cannot unmarshal object into ...
// .type of type string"), which made the fabric overview report 0 identities.
func TestZitiIdentityTypeUnmarshal(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantType string
		wantName string
	}{
		{
			name:     "type as string",
			body:     `{"id":"a","name":"router-one","type":"Router"}`,
			wantType: "Router",
			wantName: "router-one",
		},
		{
			name:     "type as object with name",
			body:     `{"id":"b","name":"dev-two","type":{"id":"Device","name":"Device"}}`,
			wantType: "Device",
			wantName: "dev-two",
		},
		{
			name:     "type as object with only id",
			body:     `{"id":"c","name":"svc-three","type":{"id":"Service"}}`,
			wantType: "Service",
			wantName: "svc-three",
		},
		{
			name:     "type absent",
			body:     `{"id":"d","name":"no-type"}`,
			wantType: "",
			wantName: "no-type",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var id ZitiIdentityInfo
			if err := json.Unmarshal([]byte(tc.body), &id); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if id.Type != tc.wantType {
				t.Errorf("Type = %q, want %q", id.Type, tc.wantType)
			}
			if id.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", id.Name, tc.wantName)
			}
		})
	}
}

// TestZitiIdentityListDecodesMixedTypes proves a list containing both type
// shapes decodes fully instead of erroring on the first object-typed entry.
func TestZitiIdentityListDecodesMixedTypes(t *testing.T) {
	body := `[
		{"id":"1","name":"a","type":"Router"},
		{"id":"2","name":"b","type":{"id":"Device","name":"Device"}},
		{"id":"3","name":"c","type":{"id":"Service","name":"Service"}}
	]`
	var ids []ZitiIdentityInfo
	if err := json.Unmarshal([]byte(body), &ids); err != nil {
		t.Fatalf("list unmarshal failed: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("decoded %d identities, want 3", len(ids))
	}
	want := []string{"Router", "Device", "Service"}
	for i, w := range want {
		if ids[i].Type != w {
			t.Errorf("ids[%d].Type = %q, want %q", i, ids[i].Type, w)
		}
	}
}
