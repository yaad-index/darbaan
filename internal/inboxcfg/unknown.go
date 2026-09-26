package inboxcfg

import (
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// gateKeys are the Authentication-Results gate's settings (ADR 0031). They are
// settings of an inbox's trust block only, so anywhere else under trust, such as
// inside a per-sender rule, the decoder drops them, and an operator who put them
// there would believe that rule is gated when it is not (#237, A1).
var gateKeys = map[string]bool{
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

// rejectMisplacedGate fails for any unknown key that names a gate setting under
// an inbox's trust, which can only be one the decoder drops (a per-sender rule has
// no such setting), so that configuration fails loudly instead of silently loading
// an ungated rule.
func rejectMisplacedGate(unknown []string) error {
	for _, p := range unknown {
		key := p[strings.LastIndex(p, ".")+1:]
		if gateKeys[key] && strings.Contains(p+".", ".trust.") && strings.HasPrefix(p, "inboxes[") {
			return fmt.Errorf("inboxcfg: %s: the Authentication-Results gate (ADR 0031) is set per inbox, as trust.%s, "+
				"and gates every trusted outcome of that inbox; here it would do nothing. Move it", p, key)
		}
	}
	return nil
}
