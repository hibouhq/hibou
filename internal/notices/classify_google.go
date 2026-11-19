package notices

import (
	"fmt"
	"strings"

	classifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"
)

// minClassifierConfidence is the threshold under which a match is not
// trusted. ADR-051's spike (Rollout step 1) is to tune it per ecosystem.
const minClassifierConfidence = 0.9

// googleClassifier adapts github.com/google/licenseclassifier/v2 (ADR-051
// §2, option E4): the classifier behind go-licenses, with its embedded
// licence corpus. This file is the only one that imports it.
type googleClassifier struct{ c *classifier.Classifier }

// NewClassifier loads the embedded licence corpus.
func NewClassifier() (Classifier, error) {
	c, err := assets.DefaultClassifier()
	if err != nil {
		return nil, fmt.Errorf("load licence classifier: %w", err)
	}
	return &googleClassifier{c: c}, nil
}

func (g *googleClassifier) Classify(text []byte) (string, float64) {
	var ids []string
	confidence := 1.0
	for _, match := range g.c.Match(text).Matches {
		if match.MatchType != "License" || match.Confidence < minClassifierConfidence {
			continue
		}
		ids = append(ids, match.Name)
		if match.Confidence < confidence {
			confidence = match.Confidence
		}
	}
	if len(ids) == 0 {
		return "", 0
	}
	return strings.Join(uniqueSorted(ids), " AND "), confidence
}

func (g *googleClassifier) Version() string { return "licenseclassifier/v2@v2.0.0" }
