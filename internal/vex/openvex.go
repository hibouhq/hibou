package vex

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type openVEXDocument struct {
	Context    any                `json:"@context"`
	ID         string             `json:"@id"`
	Timestamp  string             `json:"timestamp"`
	Statements []openVEXStatement `json:"statements"`
}

type openVEXStatement struct {
	Vulnerability struct {
		ID string `json:"@id"`
	} `json:"vulnerability"`
	Products []struct {
		ID string `json:"@id"`
	} `json:"products"`
	Status          string `json:"status"`
	Justification   string `json:"justification"`
	ImpactStatement string `json:"impact_statement"`
	ActionStatement string `json:"action_statement"`
	Supplier        string `json:"supplier"`
	Source          string `json:"source"`
}

func ParseOpenVEX(data []byte) (*ParseResult, error) {
	var doc openVEXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode openvex document: %w", err)
	}
	if !openVEXContext(doc.Context) {
		return nil, errors.New("document is not openvex")
	}

	statements := make([]Statement, 0, len(doc.Statements))
	for _, item := range doc.Statements {
		statement := Statement{
			VulnerabilityID: item.Vulnerability.ID,
			Status:          strings.TrimSpace(item.Status),
			Justification:   strings.TrimSpace(item.Justification),
			ImpactStatement: strings.TrimSpace(item.ImpactStatement),
			ActionStatement: strings.TrimSpace(item.ActionStatement),
			Supplier:        strings.TrimSpace(item.Supplier),
		}
		if len(item.Products) > 0 {
			statement.ComponentPURL = strings.TrimSpace(item.Products[0].ID)
		}
		if strings.TrimSpace(item.Source) != "" {
			statement.SourceDocumentURL = strings.TrimSpace(item.Source)
		}
		if statement.VulnerabilityID == "" || statement.Status == "" {
			continue
		}
		if len(item.Products) == 0 {
			statements = append(statements, statement)
			continue
		}
		for _, product := range item.Products {
			productStatement := statement
			productStatement.ComponentPURL = strings.TrimSpace(product.ID)
			statements = append(statements, productStatement)
		}
	}

	return &ParseResult{
		Format:     FormatOpenVEX,
		Statements: statements,
		DocumentID: strings.TrimSpace(doc.ID),
		Timestamp:  strings.TrimSpace(doc.Timestamp),
	}, nil
}

func openVEXContext(value any) bool {
	switch typed := value.(type) {
	case string:
		return strings.Contains(typed, "openvex.dev")
	case []any:
		for _, item := range typed {
			if openVEXContext(item) {
				return true
			}
		}
	}
	return false
}
