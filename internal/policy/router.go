package policy

// Chain names an approval path. The router selects one from a risk verdict; the
// chain then resolves to an ordered list of approver names (ADR 0005).
type Chain string

const (
	// StrictChain is the cautious path (medium/high risk, or any flag, or no
	// risk signal at all).
	StrictChain Chain = "strict"
	// LightChain is the low-friction path (low risk, no flags).
	LightChain Chain = "light"
)

// Risk is the coarse pre-screener verdict that selects a chain (ADR 0005). v1
// has no pre-screener, so the router is always called with a nil Risk.
type Risk struct {
	Level string   // "low" | "medium" | "high"
	Flags []string // e.g. touches-secret, new-recipient, external-domain, has-attachment
}

// Router maps a risk verdict to an approval chain and resolves the chain to its
// approver names. The name lists are configured; v1 wires both chains to the
// single manual approver.
type Router struct {
	strict []string
	light  []string
}

// NewRouter builds a router with the approver-name lists for each chain.
func NewRouter(strict, light []string) *Router {
	return &Router{strict: strict, light: light}
}

// Select returns the chain for the given risk and its ordered approver names.
//
// A nil risk means no pre-screener is compiled in. Absence of a risk signal is
// treated as "could be risky," never as low: the router returns the strict
// chain (the fail-safe of ADR 0005). A non-nil low risk with no flags takes the
// light chain; anything else takes strict.
func (r *Router) Select(risk *Risk) (Chain, []string) {
	if risk == nil {
		return StrictChain, r.strict
	}
	if risk.Level == "low" && len(risk.Flags) == 0 {
		return LightChain, r.light
	}
	return StrictChain, r.strict
}
