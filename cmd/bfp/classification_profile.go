package main

import (
	"encoding/json"
	"errors"
)

// Profiles change local scheduling policy; they never change stream delivery,
// authentication, flow credit, carrier health or negotiated repair semantics.
func keygenClassificationProfile(name string) (json.RawMessage, error) {
	switch name {
	case "standard":
		return nil, nil
	case "low-bandwidth":
		policy := json.RawMessage(`{
			"default_class":"normal",
			"rules":[
				{"name":"dns","network":"udp","ports":[{"first":53,"last":53}],"class":"interactive","locked":true},
				{"name":"ssh","network":"tcp","ports":[{"first":22,"last":22}],"class":"interactive","locked":true}
			],
			"behavior":{
				"min_total_bytes":32768,
				"bulk_bytes_per_second":8192,
				"restore_bytes_per_second":2048
			}
		}`)
		if _, err := configClassification(policy); err != nil {
			return nil, err
		}
		return policy, nil
	default:
		return nil, errors.New("classification profile must be standard or low-bandwidth")
	}
}
