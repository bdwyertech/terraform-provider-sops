package sops

import "fmt"

// flatten flattens the nested struct.
//
// All keys will be joined by dot
// e.g. {"a": {"b":"c"}} => {"a.b":"c"}
// or {"a": {"b":[1,2]}} => {"a.b.0":1, "a.b.1": 2}
func flatten(data map[string]interface{}) map[string]string {
	ret := make(map[string]string)
	for k, v := range data {
		switch typed := v.(type) {
		case map[interface{}]interface{}:
			for fk, fv := range flatten(convertMap(typed)) {
				ret[fmt.Sprintf("%s.%s", k, fk)] = fv
			}
		case map[string]interface{}:
			for fk, fv := range flatten(typed) {
				ret[fmt.Sprintf("%s.%s", k, fk)] = fv
			}
		case []interface{}:
			for fk, fv := range flattenSlice(typed) {
				ret[fmt.Sprintf("%s.%s", k, fk)] = fv
			}
		case nil:
			ret[k] = "null"
		default:
			ret[k] = fmt.Sprint(typed)
		}
	}
	return ret
}

func flattenSlice(data []interface{}) map[string]string {
	ret := make(map[string]string)
	for idx, v := range data {
		switch typed := v.(type) {
		case map[interface{}]interface{}:
			for fk, fv := range flatten(convertMap(typed)) {
				ret[fmt.Sprintf("%d.%s", idx, fk)] = fv
			}
		case map[string]interface{}:
			for fk, fv := range flatten(typed) {
				ret[fmt.Sprintf("%d.%s", idx, fk)] = fv
			}
		case []interface{}:
			for fk, fv := range flattenSlice(typed) {
				ret[fmt.Sprintf("%d.%s", idx, fk)] = fv
			}
		case nil:
			ret[fmt.Sprint(idx)] = "null"
		default:
			ret[fmt.Sprint(idx)] = fmt.Sprint(typed)
		}
	}
	return ret
}

func flattenFromKey(data map[string]interface{}, k string) (map[string]string, error) {
	ret := make(map[string]string)
	v := data[k]
	if v == nil {
		return ret, fmt.Errorf("key %s not found", k)
	}
	switch typed := v.(type) {
	case map[interface{}]interface{}:
		for fk, fv := range flatten(convertMap(typed)) {
			ret[fmt.Sprintf("%s.%s", k, fk)] = fv
		}
	case map[string]interface{}:
		for fk, fv := range flatten(typed) {
			ret[fmt.Sprintf("%s.%s", k, fk)] = fv
		}
	case []interface{}:
		for fk, fv := range flattenSlice(typed) {
			ret[fmt.Sprintf("%s.%s", k, fk)] = fv
		}
	default:
		ret[k] = fmt.Sprint(typed)
	}
	return ret, nil
}

func convertMap(originalMap map[interface{}]interface{}) map[string]interface{} {
	convertedMap := map[string]interface{}{}
	for key, value := range originalMap {
		convertedMap[key.(string)] = value
	}
	return convertedMap
}
