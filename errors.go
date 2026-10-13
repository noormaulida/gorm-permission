package permission

import "errors"

var (
	// ErrNotFound is returned when a role or permission cannot be resolved.
	ErrNotFound = errors.New("permission: not found")

	// ErrInvalidArgument is returned for empty names or unsupported inputs.
	ErrInvalidArgument = errors.New("permission: invalid argument")

	// ErrGuardMismatch is returned when a role/permission guard does not match
	// the model's expected guard.
	ErrGuardMismatch = errors.New("permission: guard mismatch")
)
