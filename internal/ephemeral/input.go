package ephemeral

import "fmt"

// InputError is a rejected argument. Reason is a fixed description without
// caller data, safe for telemetry. Err is the message for the caller, which
// can quote paths, names, or other input.
type InputError struct {
	Reason string
	Err    error
}

func (e *InputError) Error() string { return e.Err.Error() }

func (e *InputError) Unwrap() error { return e.Err }

// InvalidInput returns an InputError with the given reason and message.
func InvalidInput(reason, format string, args ...any) error {
	return &InputError{Reason: reason, Err: fmt.Errorf(format, args...)}
}
