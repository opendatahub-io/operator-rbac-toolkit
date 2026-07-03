package scoper

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/types"
)

type OwnerEntry struct {
	Namespace string
	Name      string
	UID       types.UID
}

func ParseOwnerAnnotation(value string) []OwnerEntry {
	if value == "" {
		return nil
	}
	var entries []OwnerEntry
	for _, part := range strings.Split(value, ",") {
		entry, ok := parseOwnerEntry(strings.TrimSpace(part))
		if ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

func parseOwnerEntry(s string) (OwnerEntry, bool) {
	parts := strings.SplitN(s, "/", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return OwnerEntry{}, false
	}
	return OwnerEntry{
		Namespace: parts[0],
		Name:      parts[1],
		UID:       types.UID(parts[2]),
	}, true
}

func FormatOwnerAnnotation(entries []OwnerEntry) string {
	parts := make([]string, len(entries))
	for i, e := range entries {
		parts[i] = fmt.Sprintf("%s/%s/%s", e.Namespace, e.Name, string(e.UID))
	}
	return strings.Join(parts, ",")
}

// AddOwnerEntry appends a new OwnerEntry if its UID is not already present.
// Entries whose Namespace or Name contain "/" or "," are skipped because those
// characters are used as delimiters in the serialized annotation format and
// would corrupt parsing.
func AddOwnerEntry(entries []OwnerEntry, entry OwnerEntry) []OwnerEntry {
	if strings.ContainsAny(entry.Namespace, "/,") || strings.ContainsAny(entry.Name, "/,") {
		return entries
	}
	for _, e := range entries {
		if e.UID == entry.UID {
			return entries
		}
	}
	return append(entries, entry)
}

func RemoveOwnerEntry(entries []OwnerEntry, uid types.UID) []OwnerEntry {
	var result []OwnerEntry
	for _, e := range entries {
		if e.UID != uid {
			result = append(result, e)
		}
	}
	return result
}
