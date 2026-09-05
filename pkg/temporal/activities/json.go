package activities

import "encoding/json"

func jsonEncode(v any) ([]byte, error) { return json.Marshal(v) }
