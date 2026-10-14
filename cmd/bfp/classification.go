package main

import (
	"bfp/classification"
	"bfp/internal/configjson"
	"bfp/protocol"
	"encoding/json"
)

func configFieldError(path, reason string) error { return configjson.FieldError(path, reason) }
func configObject(raw json.RawMessage, path string, allowed ...string) (map[string]json.RawMessage, error) {
	return configjson.Object(raw, path, allowed...)
}
func checkConfigJSONValue(dec *json.Decoder, depth int) error {
	return configjson.CheckValue(dec, depth)
}
func checkConfigEntryKeys(body []byte) error { return configjson.CheckEntryKeys(body) }
func configString(raw json.RawMessage, path string) (string, error) {
	return configjson.String(raw, path)
}
func validConfigSurrogates(raw []byte) bool { return configjson.ValidSurrogates(raw) }
func configClass(raw json.RawMessage, path string) (protocol.Class, error) {
	return configjson.Class(raw, path)
}
func configBool(raw json.RawMessage, path string) (bool, error) { return configjson.Bool(raw, path) }
func configUint(raw json.RawMessage, path string, maximum uint64) (uint64, error) {
	return configjson.Uint(raw, path, maximum)
}
func configArray(raw json.RawMessage, path string, limit int, nonempty bool) ([]json.RawMessage, error) {
	return configjson.Array(raw, path, limit, nonempty)
}
func configDomain(value, path string) error { return configjson.Domain(value, path) }
func configRule(raw json.RawMessage, index int) (classification.Rule, error) {
	return configjson.Rule(raw, index)
}
func configBehavior(raw json.RawMessage, out *classification.BehaviorConfig) error {
	return configjson.Behavior(raw, out)
}
func configClassification(raw json.RawMessage) (*classification.Config, error) {
	return configjson.Classification(raw)
}
func configSOCKSDomainSource(raw json.RawMessage) (string, error) {
	return configjson.SOCKSDomainSource(raw)
}
