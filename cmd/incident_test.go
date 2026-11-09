package cmd

import (
	"strings"
	"testing"
	"time"
)

func TestRequireIncidentNumber(t *testing.T) {
	for input, want := range map[string]string{"12": "12", "#7": "7"} {
		got, err := requireIncidentNumber([]string{input})
		if err != nil || got != want {
			t.Fatalf("requireIncidentNumber(%q) = %q, %v", input, got, err)
		}
	}
	for _, input := range []string{"abc", "12a", ""} {
		if _, err := requireIncidentNumber([]string{input}); err == nil {
			t.Fatalf("requireIncidentNumber(%q) accepted", input)
		}
	}
	if _, err := requireIncidentNumber(nil); err == nil {
		t.Fatal("no argument accepted")
	}
}

func TestFormatDue(t *testing.T) {
	if formatDue(nil) != "-" {
		t.Fatal("nil due")
	}
	past := time.Now().Add(-2 * time.Hour)
	if got := formatDue(&past); !strings.HasPrefix(got, "overdue ") {
		t.Fatalf("past due = %q", got)
	}
	future := time.Now().Add(3 * time.Hour)
	if got := formatDue(&future); !strings.HasPrefix(got, "in ") {
		t.Fatalf("future due = %q", got)
	}
}
