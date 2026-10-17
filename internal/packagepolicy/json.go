package packagepolicy

import "encoding/json"

func unmarshalStrings(raw []byte, out *[]string) error {
	return json.Unmarshal(raw, out)
}
