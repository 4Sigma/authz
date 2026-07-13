package authz

// Request is a single authorization question: may Subject perform Action on
// the object identified by ObjectID? The resource kind is not part of the
// request: a policy is registered for exactly one resource kind, so it
// already knows which one it is deciding for.
//
// ObjectID is a string because that is how object identifiers arrive at an
// application's boundary (URL path segments, message fields); the
// ObjectLoader given to Wrap converts it to whatever the application uses
// internally. It is empty for collection-level actions such as create or
// list.
type Request[A comparable, S any] struct {
	Subject  S
	Action   A
	ObjectID string
}
