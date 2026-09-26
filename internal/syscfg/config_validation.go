package syscfg

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
)

type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ValidationError struct {
	Fields []FieldError `json:"fields"`
}

func (e *ValidationError) Error() string {
	return "invalid system configuration"
}

func (e *ValidationError) add(field, code, message string) {
	e.Fields = append(e.Fields, FieldError{Field: field, Code: code, Message: message})
}

func (e *ValidationError) err() error {
	if len(e.Fields) == 0 {
		return nil
	}
	return e
}

func validateConfigPatch(patch json.RawMessage) error {
	var validation ValidationError
	if !json.Valid(patch) {
		validation.add("$", "invalid_json", "Patch must contain one valid JSON object.")
		return &validation
	}
	validatePatchValue(bytes.TrimSpace(patch), reflect.TypeOf(Config{}), "$", &validation)
	return validation.err()
}

func validatePatchValue(raw json.RawMessage, typ reflect.Type, field string, validation *ValidationError) {
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		validation.add(field, "null_not_allowed", "Null values are not allowed.")
		return
	}
	switch typ.Kind() {
	case reflect.Struct:
		if len(raw) == 0 || raw[0] != '{' {
			validation.add(field, "invalid_type", "Value must be a JSON object.")
			return
		}
		fields := make(map[string]reflect.Type)
		for i := 0; i < typ.NumField(); i++ {
			member := typ.Field(i)
			name := strings.Split(member.Tag.Get("json"), ",")[0]
			if member.IsExported() && name != "" && name != "-" {
				fields[name] = member.Type
			}
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		seen := make(map[string]bool)
		if _, err := dec.Token(); err != nil {
			validation.add(field, "invalid_json", "Value must contain valid JSON.")
			return
		}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				validation.add(field, "invalid_json", "Value must contain valid JSON.")
				return
			}
			var value json.RawMessage
			if err := dec.Decode(&value); err != nil {
				validation.add(field, "invalid_json", "Value must contain valid JSON.")
				return
			}
			name, ok := key.(string)
			member, known := fields[name]
			if !ok || !known {
				validation.add("$", "unknown_field", "Patch contains an unknown field.")
				continue
			}
			path := name
			if field != "$" {
				path = field + "." + name
			}
			if seen[name] {
				validation.add(path, "duplicate_field", "Fields must not be repeated.")
				continue
			}
			seen[name] = true
			validatePatchValue(value, member, path, validation)
		}
	case reflect.Slice:
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			validation.add(field, "invalid_type", "Value must be a JSON array.")
			return
		}
		for _, value := range values {
			validatePatchValue(value, typ.Elem(), field, validation)
		}
	default:
		if err := json.Unmarshal(raw, reflect.New(typ).Interface()); err != nil {
			validation.add(field, "invalid_type", "Value has an invalid JSON type or is out of range.")
		}
	}
}
