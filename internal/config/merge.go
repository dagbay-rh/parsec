package config

import (
	"strconv"
)

// mergeEnvOverrides merges environment-variable config (src) into dest.
//
// Koanf's default merge replaces a YAML list when the env provider supplies a
// map with numeric keys (e.g. PARSEC_DATA_SOURCES__1__CONFIG__COMPLIANCE_API
// → data_sources.1.config.compliance_api). That wipes the list and leaves
// empty items. Numeric-keyed maps are instead overlaid onto the corresponding
// slice indices.
func mergeEnvOverrides(src, dest map[string]any) error {
	mergeMapsSliceAware(src, dest)
	return nil
}

func mergeMapsSliceAware(src, dest map[string]any) {
	for key, val := range src {
		destVal, exists := dest[key]
		if !exists {
			dest[key] = val
			continue
		}

		srcMap, srcIsMap := asStringMap(val)
		destMap, destIsMap := asStringMap(destVal)
		if srcIsMap && destIsMap {
			mergeMapsSliceAware(srcMap, destMap)
			continue
		}

		destSlice, destIsSlice := asSlice(destVal)
		if srcIsMap && destIsSlice && isNumericKeyedMap(srcMap) {
			dest[key] = overlaySlice(destSlice, srcMap)
			continue
		}

		dest[key] = val
	}
}

func overlaySlice(slice []any, indexed map[string]any) []any {
	out := make([]any, len(slice))
	copy(out, slice)

	for k, v := range indexed {
		idx, err := strconv.Atoi(k)
		if err != nil || idx < 0 {
			continue
		}
		for len(out) <= idx {
			out = append(out, map[string]any{})
		}

		srcMap, srcOk := asStringMap(v)
		destMap, destOk := asStringMap(out[idx])
		if srcOk && destOk {
			mergeMapsSliceAware(srcMap, destMap)
			continue
		}
		if srcOk && out[idx] == nil {
			out[idx] = v
			continue
		}
		out[idx] = v
	}
	return out
}

func isNumericKeyedMap(m map[string]any) bool {
	if len(m) == 0 {
		return false
	}
	for k := range m {
		if _, err := strconv.Atoi(k); err != nil {
			return false
		}
	}
	return true
}

func asStringMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func asSlice(v any) ([]any, bool) {
	switch s := v.(type) {
	case []any:
		return s, true
	default:
		return nil, false
	}
}
