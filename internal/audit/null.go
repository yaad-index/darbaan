package audit

func init() {
	Register("null", func(string) (AuditLog, error) { return nullLog{}, nil })
}

// nullLog is the disabled audit sink: it records nothing and always verifies
// clean. Selected by audit.type=null for a simple single-agent / single-approval
// deployment that does not want an audit trail.
type nullLog struct{}

func (nullLog) Append(Record) error { return nil }
func (nullLog) Verify() error       { return nil }
func (nullLog) Close() error        { return nil }
