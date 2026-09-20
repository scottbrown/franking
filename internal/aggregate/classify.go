package aggregate

// Class is the single action label that each source address carries.
type Class string

// The five classes, in the order that the action block prints them.
const (
	ClassPass     Class = "PASS"
	ClassDKIMOnly Class = "DKIM-ONLY"
	ClassSPFOnly  Class = "SPF-ONLY"
	ClassPartial  Class = "PARTIAL"
	ClassFail     Class = "FAIL"
)

// Classes returns the classes in reporting order, worst first.
func Classes() []Class {
	return []Class{ClassFail, ClassPartial, ClassSPFOnly, ClassDKIMOnly, ClassPass}
}

// Action describes what the reader should do about a class.
func (c Class) Action() string {
	switch c {
	case ClassPass:
		return "Known good sender. No action."
	case ClassDKIMOnly:
		return "DKIM aligned, SPF not. Normal for forwarded mail. No action."
	case ClassSPFOnly:
		return "Sender does not sign. Add DKIM if the sender is yours."
	case ClassPartial:
		return "Configuration is not complete. Investigate."
	case ClassFail:
		return "Unauthorized, or a sender of yours with no SPF or DKIM record. Identify the SPF domain first."
	}
	return ""
}

// Classify gives one class to a source. The two single-mechanism classes are
// tested first, because both of them also reach a 100% DMARC pass rate.
func Classify(s *Source) Class {
	if s == nil || s.Messages <= 0 {
		return ClassFail
	}
	switch {
	case s.DKIMPass == s.Messages && s.SPFPass == 0:
		return ClassDKIMOnly
	case s.SPFPass == s.Messages && s.DKIMPass == 0:
		return ClassSPFOnly
	case s.DMARCPass == s.Messages:
		return ClassPass
	case s.DMARCPass == 0:
		return ClassFail
	default:
		return ClassPartial
	}
}
