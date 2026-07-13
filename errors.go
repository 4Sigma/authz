package authz

import (
	"errors"
	"fmt"
)

var (
	// ErrNoChecker is returned by Check* when no checker is registered for
	// the requested resource kind (unless WithDenyUnknownResources is set).
	ErrNoChecker = errors.New("authz: no policy checker registered for resource")

	// ErrUnauthorized is the errors.Is target for denials returned by
	// Require and RequireObject.
	ErrUnauthorized = errors.New("authz: unauthorized")

	// ErrMissingObjectID is returned when an object-level checker receives a
	// request without an ObjectID.
	ErrMissingObjectID = errors.New("authz: action requires an object ID")

	// ErrUnexpectedObjectID is returned when a collection-only checker
	// receives a request with an ObjectID.
	ErrUnexpectedObjectID = errors.New("authz: collection-only checker received an object ID")

	// ErrNoObjectChecker is returned by CheckObject when the registered
	// checker cannot authorize already-loaded objects.
	ErrNoObjectChecker = errors.New("authz: checker cannot authorize already-loaded objects")

	// ErrObjectType is returned by CheckObject when the object is not of the
	// type the registered checker handles.
	ErrObjectType = errors.New("authz: object type does not match registered checker")
)

// UnauthorizedError is the denial returned by Require and RequireObject. It
// matches errors.Is(err, ErrUnauthorized) and carries the request context for
// callers that map denials to transport responses (e.g. HTTP 403 bodies).
// Resource and Action hold the fmt.Sprint rendering of the typed values the
// engine was called with; give R and A a String method to control it.
type UnauthorizedError struct {
	Resource string
	Action   string
	ObjectID string // empty for collection-level actions and RequireObject
}

func (e *UnauthorizedError) Error() string {
	if e.ObjectID == "" {
		return fmt.Sprintf("authz: %s on %s denied", e.Action, e.Resource)
	}
	return fmt.Sprintf("authz: %s on %s %q denied", e.Action, e.Resource, e.ObjectID)
}

func (e *UnauthorizedError) Is(target error) bool {
	return target == ErrUnauthorized
}
