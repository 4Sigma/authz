package authz

import "context"

// ResourceChecker decides object-level actions on objects of type T.
type ResourceChecker[A comparable, S, T any] interface {
	Can(ctx context.Context, subject S, action A, obj T) (bool, error)
}

// ResourceCheckerFunc adapts a function to ResourceChecker.
type ResourceCheckerFunc[A comparable, S, T any] func(ctx context.Context, subject S, action A, obj T) (bool, error)

func (f ResourceCheckerFunc[A, S, T]) Can(ctx context.Context, subject S, action A, obj T) (bool, error) {
	return f(ctx, subject, action, obj)
}

// CollectionChecker decides collection-level actions (create, list, ...),
// which have no object.
type CollectionChecker[A comparable, S any] interface {
	CanCollection(ctx context.Context, subject S, action A) (bool, error)
}

// CollectionCheckerFunc adapts a function to CollectionChecker.
type CollectionCheckerFunc[A comparable, S any] func(ctx context.Context, subject S, action A) (bool, error)

func (f CollectionCheckerFunc[A, S]) CanCollection(ctx context.Context, subject S, action A) (bool, error) {
	return f(ctx, subject, action)
}

// ObjectLoader fetches the object a Request's ObjectID refers to, converting
// the boundary-level string ID to whatever the application uses internally.
type ObjectLoader[T any] interface {
	Load(ctx context.Context, id string) (T, error)
}

// ObjectLoaderFunc adapts a function to ObjectLoader.
type ObjectLoaderFunc[T any] func(ctx context.Context, id string) (T, error)

func (f ObjectLoaderFunc[T]) Load(ctx context.Context, id string) (T, error) {
	return f(ctx, id)
}

// Wrap builds a PolicyChecker for a resource that only has object-level
// actions. Loader errors are returned as-is, so callers can tell "object not
// found" apart from a denial.
func Wrap[A comparable, S, T any](checker ResourceChecker[A, S, T], loader ObjectLoader[T]) PolicyChecker[A, S] {
	return &resourceAdapter[A, S, T]{checker: checker, loader: loader}
}

// WrapFunc is Wrap for plain functions.
func WrapFunc[A comparable, S, T any](
	checker func(ctx context.Context, subject S, action A, obj T) (bool, error),
	loader func(ctx context.Context, id string) (T, error),
) PolicyChecker[A, S] {
	return Wrap(ResourceCheckerFunc[A, S, T](checker), ObjectLoaderFunc[T](loader))
}

// WrapHybrid builds a PolicyChecker for a resource with both object-level and
// collection-level actions: requests without an ObjectID go to collection,
// the others load the object and go to resource. It panics on a nil
// collection so that a miswired resource fails at startup rather than
// silently denying; use Wrap for object-only resources.
func WrapHybrid[A comparable, S, T any](resource ResourceChecker[A, S, T], collection CollectionChecker[A, S], loader ObjectLoader[T]) PolicyChecker[A, S] {
	if collection == nil {
		panic("authz: WrapHybrid requires a CollectionChecker; use Wrap for object-only resources")
	}
	return &hybridAdapter[A, S, T]{resource: resource, collection: collection, loader: loader}
}

// WrapCollectionOnly builds a PolicyChecker for a resource that only has
// collection-level actions.
func WrapCollectionOnly[A comparable, S any](collection CollectionChecker[A, S]) PolicyChecker[A, S] {
	return &collectionOnlyAdapter[A, S]{collection: collection}
}

type resourceAdapter[A comparable, S, T any] struct {
	checker ResourceChecker[A, S, T]
	loader  ObjectLoader[T]
}

func (a *resourceAdapter[A, S, T]) Can(ctx context.Context, req Request[A, S]) (bool, error) {
	if req.ObjectID == "" {
		return false, ErrMissingObjectID
	}
	obj, err := a.loader.Load(ctx, req.ObjectID)
	if err != nil {
		return false, err
	}
	return a.checker.Can(ctx, req.Subject, req.Action, obj)
}

func (a *resourceAdapter[A, S, T]) CanObject(ctx context.Context, subject S, action A, obj any) (bool, error) {
	typed, ok := obj.(T)
	if !ok {
		return false, ErrObjectType
	}
	return a.checker.Can(ctx, subject, action, typed)
}

type hybridAdapter[A comparable, S, T any] struct {
	resource   ResourceChecker[A, S, T]
	collection CollectionChecker[A, S]
	loader     ObjectLoader[T]
}

func (a *hybridAdapter[A, S, T]) Can(ctx context.Context, req Request[A, S]) (bool, error) {
	if req.ObjectID == "" {
		return a.collection.CanCollection(ctx, req.Subject, req.Action)
	}
	obj, err := a.loader.Load(ctx, req.ObjectID)
	if err != nil {
		return false, err
	}
	return a.resource.Can(ctx, req.Subject, req.Action, obj)
}

func (a *hybridAdapter[A, S, T]) CanObject(ctx context.Context, subject S, action A, obj any) (bool, error) {
	typed, ok := obj.(T)
	if !ok {
		return false, ErrObjectType
	}
	return a.resource.Can(ctx, subject, action, typed)
}

type collectionOnlyAdapter[A comparable, S any] struct {
	collection CollectionChecker[A, S]
}

func (a *collectionOnlyAdapter[A, S]) Can(ctx context.Context, req Request[A, S]) (bool, error) {
	if req.ObjectID != "" {
		return false, ErrUnexpectedObjectID
	}
	return a.collection.CanCollection(ctx, req.Subject, req.Action)
}
