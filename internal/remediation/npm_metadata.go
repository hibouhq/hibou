package remediation

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"

	"deps.dev/util/semver"
)

var npmPackageName = regexp.MustCompile(`^(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*$`)

func validNPMName(name string) bool { return len(name) <= 214 && npmPackageName.MatchString(name) }

func checkedNPMMetadata(data []byte) ([]byte, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if versions, ok := document["versions"]; ok {
		var entries map[string]json.RawMessage
		if err := json.Unmarshal(versions, &entries); err != nil {
			return nil, err
		}
		for version, entry := range entries {
			checked, err := checkedNPMVersion(entry)
			if err != nil {
				return nil, err
			}
			entries[version] = checked
		}
		encoded, err := json.Marshal(entries)
		if err != nil {
			return nil, err
		}
		document["versions"] = encoded
		return json.Marshal(document)
	}
	return checkedNPMVersion(data)
}

func checkedNPMVersion(data []byte) ([]byte, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	for _, kind := range []string{"dependencies", "optionalDependencies", "peerDependencies"} {
		if raw, ok := document[kind]; ok {
			var requirements map[string]string
			if err := json.Unmarshal(raw, &requirements); err != nil {
				return nil, err
			}
			for name, constraint := range requirements {
				if !validNPMName(name) {
					return nil, errors.New("unsupported registry package identity")
				}
				if _, err := semver.NPM.ParseConstraint(constraint); err != nil {
					return nil, errors.New("registry metadata includes an unsupported non-registry dependency")
				}
			}
		}
	}
	if raw, ok := document["dist"]; ok {
		var dist map[string]json.RawMessage
		if err := json.Unmarshal(raw, &dist); err != nil {
			return nil, err
		}
		if encoded, ok := dist["tarball"]; ok {
			var location string
			if err := json.Unmarshal(encoded, &location); err != nil {
				return nil, err
			}
			u, err := url.Parse(location)
			if err != nil || u.Host != "registry.npmjs.org" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
				return nil, errors.New("registry tarball redirects outside the approved profile")
			}
			u.Scheme = "https"
			dist["tarball"], err = json.Marshal(u.String())
			if err != nil {
				return nil, err
			}
		}
		encoded, err := json.Marshal(dist)
		if err != nil {
			return nil, err
		}
		document["dist"] = encoded
	}
	return json.Marshal(document)
}
