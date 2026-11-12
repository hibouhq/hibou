package server

import (
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"strings"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

type managedMaintenanceMapping struct {
	ID             string `json:"id"`
	TagPattern     string `json:"tag_pattern"`
	TargetTemplate string `json:"target_template"`
}

type managedMaintenanceSettings struct {
	AllowCreation bool                        `json:"allow_creation"`
	Mappings      []managedMaintenanceMapping `json:"mappings"`
}

var managedMappingID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
var managedReleaseVersion = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

func (s managedMaintenanceSettings) validate() error {
	if len(s.Mappings) > 50 {
		return errors.New("at most 50 explicit maintenance mappings are allowed")
	}
	seen := map[string]bool{}
	for _, mapping := range s.Mappings {
		if !managedMappingID.MatchString(mapping.ID) || seen[mapping.ID] {
			return errors.New("mapping IDs must be unique alphanumeric identifiers")
		}
		seen[mapping.ID] = true
		if len(mapping.TagPattern) == 0 || len(mapping.TagPattern) > 200 || strings.ContainsAny(mapping.TagPattern, "\x00\r\n") {
			return errors.New("a bounded source tag pattern is required")
		}
		if _, err := path.Match(mapping.TagPattern, "v1.2.3"); err != nil {
			return errors.New("invalid source tag pattern")
		}
		if len(mapping.TargetTemplate) == 0 || len(mapping.TargetTemplate) > 200 {
			return errors.New("a bounded explicit target template is required")
		}
		template := strings.NewReplacer("{major}", "1", "{minor}", "2", "{patch}", "3", "{tag}", "v1.2.3").Replace(mapping.TargetTemplate)
		if err := forge.ValidateMaintenanceRef(template); err != nil {
			return errors.New("target template must be a safe branch name using only {major}, {minor}, {patch}, or {tag}")
		}
	}
	return nil
}

func parseManagedMaintenanceSettings(org *store.Organization) (managedMaintenanceSettings, error) {
	settings := managedMaintenanceSettings{Mappings: []managedMaintenanceMapping{}}
	if len(org.Settings) == 0 {
		return settings, nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(org.Settings, &raw); err != nil {
		return settings, err
	}
	if body := raw["managed_remediation_targets"]; len(body) > 0 {
		if err := json.Unmarshal(body, &settings); err != nil {
			return settings, err
		}
	}
	if settings.Mappings == nil {
		settings.Mappings = []managedMaintenanceMapping{}
	}
	return settings, settings.validate()
}

func (mapping managedMaintenanceMapping) target(tag string) (string, bool, error) {
	matched, err := path.Match(mapping.TagPattern, tag)
	if err != nil || !matched {
		return "", matched, err
	}
	template := strings.ReplaceAll(mapping.TargetTemplate, "{tag}", tag)
	version := managedReleaseVersion.FindStringSubmatch(path.Base(tag))
	if strings.Contains(template, "{major}") || strings.Contains(template, "{minor}") || strings.Contains(template, "{patch}") {
		if len(version) != 4 {
			return "", true, errors.New("this mapping requires a semantic-version source tag")
		}
		template = strings.NewReplacer("{major}", version[1], "{minor}", version[2], "{patch}", version[3]).Replace(template)
	}
	if err := forge.ValidateMaintenanceRef(template); err != nil {
		return "", true, err
	}
	return template, true, nil
}
