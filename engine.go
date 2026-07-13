package authz

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// Engine dispatches authorization checks to the PolicyChecker registered for
// each resource kind. The resource type R and the action type A are
// comparable identifier types chosen by the application: plain strings work,
// named string types document intent, opaque struct types make forged
// literals impossible (see the README). The subject type S is the
// application's user or principal type. The engine never inspects any of
// them; R and A are rendered with fmt.Sprint only in denial errors and logs,
// so give them a String method for readable output.
type Engine[R, A comparable, S any] struct {
	mu       sync.RWMutex
	checkers map[R]PolicyChecker[A, S]

	denyUnknownResources bool
	logger               *slog.Logger
}

// engineConfig collects the settings applied while building an Engine; its
// zero value holds the defaults.
type engineConfig struct {
	denyUnknownResources bool
	logger               *slog.Logger
}

// A ConfigModifier mutates one setting of an engineConfig. Each With*
// constructor returns one; NewEngine folds them, in order, over the default
// configuration.
type ConfigModifier func(*engineConfig)

// WithDenyUnknownResources makes checks on resource kinds with no registered
// checker return a plain denial (fail closed) instead of ErrNoChecker.
func WithDenyUnknownResources() ConfigModifier {
	return func(cfg *engineConfig) { cfg.denyUnknownResources = true }
}

// WithLogger enables Warn-level logging of the denials returned by Require
// and RequireObject. The subject is never logged.
func WithLogger(l *slog.Logger) ConfigModifier {
	return func(cfg *engineConfig) { cfg.logger = l }
}

func NewEngine[R, A comparable, S any](modifiers ...ConfigModifier) *Engine[R, A, S] {
	var cfg engineConfig
	for _, modify := range modifiers {
		modify(&cfg)
	}
	return &Engine[R, A, S]{
		checkers:             make(map[R]PolicyChecker[A, S]),
		denyUnknownResources: cfg.denyUnknownResources,
		logger:               cfg.logger,
	}
}

// Register binds a checker to a resource kind, replacing any previous one.
func (e *Engine[R, A, S]) Register(resource R, checker PolicyChecker[A, S]) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.checkers[resource] = checker
}

// RegisterFunc is Register for a plain function.
func (e *Engine[R, A, S]) RegisterFunc(resource R, fn func(ctx context.Context, req Request[A, S]) (bool, error)) {
	e.Register(resource, PolicyCheckerFunc[A, S](fn))
}

// Check reports whether subject may perform action on the object of the given
// resource kind identified by objectID (empty for collection-level actions).
func (e *Engine[R, A, S]) Check(ctx context.Context, subject S, resource R, action A, objectID string) (bool, error) {
	checker, ok := e.lookup(resource)
	if !ok {
		if e.denyUnknownResources {
			return false, nil
		}
		return false, ErrNoChecker
	}
	return checker.Can(ctx, Request[A, S]{Subject: subject, Action: action, ObjectID: objectID})
}

// Require is Check returning *UnauthorizedError on denial instead of a bool.
func (e *Engine[R, A, S]) Require(ctx context.Context, subject S, resource R, action A, objectID string) error {
	allowed, err := e.Check(ctx, subject, resource, action, objectID)
	if err != nil {
		return err
	}
	if !allowed {
		denial := &UnauthorizedError{Resource: fmt.Sprint(resource), Action: fmt.Sprint(action), ObjectID: objectID}
		e.logDenial(ctx, denial)
		return denial
	}
	return nil
}

// CheckObject is Check for an object the caller has already loaded, skipping
// the ObjectLoader round-trip. The registered checker must implement
// ObjectChecker (checkers built with Wrap and WrapHybrid do).
func (e *Engine[R, A, S]) CheckObject(ctx context.Context, subject S, resource R, action A, obj any) (bool, error) {
	checker, ok := e.lookup(resource)
	if !ok {
		if e.denyUnknownResources {
			return false, nil
		}
		return false, ErrNoChecker
	}
	oc, ok := checker.(ObjectChecker[A, S])
	if !ok {
		return false, ErrNoObjectChecker
	}
	return oc.CanObject(ctx, subject, action, obj)
}

// RequireObject is CheckObject returning *UnauthorizedError on denial instead
// of a bool.
func (e *Engine[R, A, S]) RequireObject(ctx context.Context, subject S, resource R, action A, obj any) error {
	allowed, err := e.CheckObject(ctx, subject, resource, action, obj)
	if err != nil {
		return err
	}
	if !allowed {
		denial := &UnauthorizedError{Resource: fmt.Sprint(resource), Action: fmt.Sprint(action)}
		e.logDenial(ctx, denial)
		return denial
	}
	return nil
}

// HasChecker reports whether a checker is registered for the resource kind,
// e.g. for boot-time wiring assertions.
func (e *Engine[R, A, S]) HasChecker(resource R) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.checkers[resource]
	return ok
}

// Resources returns the registered resource kinds, in no particular order.
func (e *Engine[R, A, S]) Resources() []R {
	e.mu.RLock()
	defer e.mu.RUnlock()
	resources := make([]R, 0, len(e.checkers))
	for r := range e.checkers {
		resources = append(resources, r)
	}
	return resources
}

func (e *Engine[R, A, S]) lookup(resource R) (PolicyChecker[A, S], bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	checker, ok := e.checkers[resource]
	return checker, ok
}

func (e *Engine[R, A, S]) logDenial(ctx context.Context, denial *UnauthorizedError) {
	if e.logger == nil {
		return
	}
	e.logger.LogAttrs(ctx, slog.LevelWarn, "authorization denied",
		slog.String("resource", denial.Resource),
		slog.String("action", denial.Action),
		slog.String("object_id", denial.ObjectID),
	)
}
