package authz

import "context"

// PolicyChecker decides authorization requests for one resource kind.
type PolicyChecker[A comparable, S any] interface {
	Can(ctx context.Context, req Request[A, S]) (bool, error)
}

// PolicyCheckerFunc adapts a function to PolicyChecker.
type PolicyCheckerFunc[A comparable, S any] func(ctx context.Context, req Request[A, S]) (bool, error)

func (f PolicyCheckerFunc[A, S]) Can(ctx context.Context, req Request[A, S]) (bool, error) {
	return f(ctx, req)
}

// ObjectChecker is implemented by checkers that can also decide on an
// already-loaded object, letting Engine.CheckObject skip the ObjectLoader
// round-trip. Checkers built with Wrap and WrapHybrid implement it.
type ObjectChecker[A comparable, S any] interface {
	CanObject(ctx context.Context, subject S, action A, obj any) (bool, error)
}
