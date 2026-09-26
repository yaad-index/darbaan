package inboxcfg

import (
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// unimplementedTrustKeys are settings ADR 0031 describes that no code implements
// yet. The config decoder is not strict, so without this check they would load
// and do nothing, and an operator who set them would believe trusted elevation is
// gated on authentication when it is not (#237, A1).
var unimplementedTrustKeys = map[string]bool{
	"require_authenticated": true,
	"authserv_id":           true,
}

// UnknownKeys returns the path of every key under `inboxes:` that the config
// decoder ignores because no setting has that name, such as a misspelled or
// unsupported key. The decoder is not strict, so these load silently; this is how
// they are made visible. An absent `inboxes:` returns nil.
func UnknownKeys(data []byte) ([]string, error) {
	var doc struct {
		Inboxes yaml.Node `yaml:"inboxes"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("inboxcfg: parse: %w", err)
	}
	if doc.Inboxes.IsZero() {
		return nil, nil
	}
	var out []string
	unknownIn(&doc.Inboxes, reflect.TypeOf([]Inbox{}), "inboxes", &out)
	return out, nil
}

// unknownIn walks node against t, the Go type it decodes into, appending the path
// of every mapping key that matches no field's yaml name.
func unknownIn(node *yaml.Node, t reflect.Type, path string, out *[]string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case node.Kind == yaml.SequenceNode && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array):
		for i, item := range node.Content {
			unknownIn(item, t.Elem(), fmt.Sprintf("%s[%d]", path, i), out)
		}
	case node.Kind == yaml.MappingNode && t.Kind() == reflect.Struct:
		fields := yamlFields(t)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			ft, ok := fields[key]
			if !ok {
				*out = append(*out, path+"."+key)
				continue
			}
			unknownIn(node.Content[i+1], ft, path+"."+key, out)
		}
	case node.Kind == yaml.MappingNode && t.Kind() == reflect.Map:
		for i := 0; i+1 < len(node.Content); i += 2 {
			unknownIn(node.Content[i+1], t.Elem(), path+"."+node.Content[i].Value, out)
		}
	}
}

// yamlFields maps each yaml key name of struct t to its field's type, following
// inlined structs the way the decoder does.
func yamlFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("yaml")
		name, opts, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if strings.Contains(opts, "inline") {
			for k, v := range yamlFields(f.Type) {
				out[k] = v
			}
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		out[name] = f.Type
	}
	return out
}

// rejectUnimplemented fails for any unknown key that names a setting ADR 0031
// describes but no code implements, anywhere under an inbox's trust (including
// inside a per-sender rule), so that configuration fails loudly instead of silently
// loading an unprotected setup.
func rejectUnimplemented(unknown []string) error {
	for _, p := range unknown {
		key := p[strings.LastIndex(p, ".")+1:]
		if unimplementedTrustKeys[key] && strings.Contains(p+".", ".trust.") && strings.HasPrefix(p, "inboxes[") {
			return fmt.Errorf("inboxcfg: %s: the Authentication-Results gate (ADR 0031) is not implemented yet, so this setting would do nothing; "+
				"trusted elevation currently relies on the upstream's own sender authentication. Remove it", p)
		}
	}
	return nil
}
