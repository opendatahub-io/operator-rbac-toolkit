package scoper

import (
	"testing"

	"k8s.io/apimachinery/pkg/types"
)

func TestParseOwnerAnnotation(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"empty", "", 0},
		{"single", "ns/name/uid-123", 1},
		{"multiple", "ns1/name1/uid-1,ns2/name2/uid-2", 2},
		{"malformed skipped", "ns/name/uid,bad-entry,ns2/name2/uid2", 2},
		{"all malformed", "bad,worse,", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseOwnerAnnotation(tt.input)
			if len(result) != tt.expected {
				t.Errorf("expected %d entries, got %d", tt.expected, len(result))
			}
		})
	}
}

func TestFormatOwnerAnnotation(t *testing.T) {
	entries := []OwnerEntry{
		{Namespace: "ns1", Name: "cr1", UID: "uid-1"},
		{Namespace: "ns2", Name: "cr2", UID: "uid-2"},
	}
	result := FormatOwnerAnnotation(entries)
	expected := "ns1/cr1/uid-1,ns2/cr2/uid-2"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestAddOwnerEntry(t *testing.T) {
	entries := []OwnerEntry{
		{Namespace: "ns1", Name: "cr1", UID: "uid-1"},
	}

	added := AddOwnerEntry(entries, OwnerEntry{Namespace: "ns2", Name: "cr2", UID: "uid-2"})
	if len(added) != 2 {
		t.Errorf("expected 2 entries, got %d", len(added))
	}

	duplicate := AddOwnerEntry(added, OwnerEntry{Namespace: "ns1", Name: "cr1", UID: "uid-1"})
	if len(duplicate) != 2 {
		t.Errorf("expected 2 entries (no duplicate), got %d", len(duplicate))
	}
}

func TestRemoveOwnerEntry(t *testing.T) {
	entries := []OwnerEntry{
		{Namespace: "ns1", Name: "cr1", UID: "uid-1"},
		{Namespace: "ns2", Name: "cr2", UID: "uid-2"},
	}

	result := RemoveOwnerEntry(entries, types.UID("uid-1"))
	if len(result) != 1 {
		t.Errorf("expected 1 entry, got %d", len(result))
	}
	if result[0].UID != "uid-2" {
		t.Errorf("expected uid-2, got %s", result[0].UID)
	}
}

func TestRoundtrip(t *testing.T) {
	original := []OwnerEntry{
		{Namespace: "ns1", Name: "cr1", UID: "uid-1"},
		{Namespace: "ns2", Name: "cr2", UID: "uid-2"},
	}
	serialized := FormatOwnerAnnotation(original)
	parsed := ParseOwnerAnnotation(serialized)

	if len(parsed) != len(original) {
		t.Fatalf("roundtrip length mismatch: %d vs %d", len(parsed), len(original))
	}
	for i := range original {
		if parsed[i] != original[i] {
			t.Errorf("entry %d mismatch: %+v vs %+v", i, parsed[i], original[i])
		}
	}
}
