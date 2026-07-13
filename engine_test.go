package authz_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"labcatch/authz"
)

// testUser is the subject type used across the tests, playing the role of an
// application's user struct.
type testUser struct {
	ID   string
	Role string
}

type testDocument struct {
	ID      string
	OwnerID string
}

type testDocumentPolicy struct{}

func (testDocumentPolicy) Can(_ context.Context, user testUser, action string, doc testDocument) (bool, error) {
	switch action {
	case "read":
		return true, nil
	case "update", "delete":
		return doc.OwnerID == user.ID, nil
	default:
		return false, nil
	}
}

var errDocumentNotFound = errors.New("document not found")

type testDocumentLoader struct {
	docs map[string]testDocument
}

func (l testDocumentLoader) Load(_ context.Context, id string) (testDocument, error) {
	doc, ok := l.docs[id]
	if !ok {
		return testDocument{}, errDocumentNotFound
	}
	return doc, nil
}

type testCollectionPolicy struct{}

func (testCollectionPolicy) CanCollection(_ context.Context, user testUser, action string) (bool, error) {
	switch action {
	case "list":
		return true, nil
	case "create":
		return user.Role != "guest", nil
	default:
		return false, nil
	}
}

func newTestLoader() testDocumentLoader {
	return testDocumentLoader{
		docs: map[string]testDocument{
			"doc-1": {ID: "doc-1", OwnerID: "user-123"},
			"doc-2": {ID: "doc-2", OwnerID: "user-456"},
		},
	}
}

func adminOnlyChecker(_ context.Context, req authz.Request[string, testUser]) (bool, error) {
	return req.Subject.Role == "admin", nil
}

func TestCheck_UnknownResource(t *testing.T) {
	t.Run("returns ErrNoChecker by default", func(t *testing.T) {
		engine := authz.NewEngine[string, string, testUser]()
		_, err := engine.Check(context.Background(), testUser{}, "unknown", "read", "123")
		if !errors.Is(err, authz.ErrNoChecker) {
			t.Errorf("expected ErrNoChecker, got %v", err)
		}
	})

	t.Run("denies without error with WithDenyUnknownResources", func(t *testing.T) {
		engine := authz.NewEngine[string, string, testUser](authz.WithDenyUnknownResources())
		allowed, err := engine.Check(context.Background(), testUser{}, "unknown", "read", "123")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if allowed {
			t.Error("expected false, got true")
		}
	})
}

func TestCheck_DelegatesToRegisteredChecker(t *testing.T) {
	engine := authz.NewEngine[string, string, testUser]()
	engine.RegisterFunc("document", adminOnlyChecker)

	allowed, err := engine.Check(context.Background(), testUser{Role: "admin"}, "document", "read", "123")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !allowed {
		t.Error("expected allowed to be true")
	}

	allowed, err = engine.Check(context.Background(), testUser{Role: "guest"}, "document", "read", "123")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if allowed {
		t.Error("expected allowed to be false")
	}
}

func TestRequire(t *testing.T) {
	engine := authz.NewEngine[string, string, testUser]()
	engine.RegisterFunc("document", adminOnlyChecker)

	t.Run("returns nil when authorized", func(t *testing.T) {
		err := engine.Require(context.Background(), testUser{Role: "admin"}, "document", "read", "123")
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("returns UnauthorizedError with request context when denied", func(t *testing.T) {
		err := engine.Require(context.Background(), testUser{Role: "guest"}, "document", "read", "123")
		if !errors.Is(err, authz.ErrUnauthorized) {
			t.Fatalf("expected ErrUnauthorized, got %v", err)
		}
		var uerr *authz.UnauthorizedError
		if !errors.As(err, &uerr) {
			t.Fatalf("expected *UnauthorizedError, got %T", err)
		}
		if uerr.Resource != "document" || uerr.Action != "read" || uerr.ObjectID != "123" {
			t.Errorf("unexpected error context: %+v", uerr)
		}
	})

	t.Run("propagates checker errors as-is", func(t *testing.T) {
		err := engine.Require(context.Background(), testUser{}, "unknown", "read", "123")
		if !errors.Is(err, authz.ErrNoChecker) {
			t.Errorf("expected ErrNoChecker, got %v", err)
		}
	})
}

func TestUnauthorizedError_Message(t *testing.T) {
	withID := &authz.UnauthorizedError{Resource: "document", Action: "update", ObjectID: "doc-1"}
	if got, want := withID.Error(), `authz: update on document "doc-1" denied`; got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
	withoutID := &authz.UnauthorizedError{Resource: "document", Action: "create"}
	if got, want := withoutID.Error(), "authz: create on document denied"; got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestWrapFunc(t *testing.T) {
	loader := newTestLoader()
	engine := authz.NewEngine[string, string, testUser]()
	engine.Register("document", authz.WrapFunc(
		func(_ context.Context, user testUser, _ string, doc testDocument) (bool, error) {
			return doc.OwnerID == user.ID, nil
		},
		loader.Load,
	))
	engine.Register("report", authz.WrapCollectionOnly(authz.CollectionCheckerFunc[string, testUser](
		func(_ context.Context, user testUser, _ string) (bool, error) {
			return user.Role == "admin", nil
		},
	)))

	allowed, err := engine.Check(context.Background(), testUser{ID: "user-123"}, "document", "update", "doc-1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !allowed {
		t.Error("expected allowed to be true")
	}

	allowed, err = engine.Check(context.Background(), testUser{Role: "admin"}, "report", "list", "")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !allowed {
		t.Error("expected allowed to be true")
	}
}

func TestWrap(t *testing.T) {
	engine := authz.NewEngine[string, string, testUser]()
	engine.Register("document", authz.Wrap(testDocumentPolicy{}, newTestLoader()))

	tests := []struct {
		name     string
		user     testUser
		action   string
		objectID string
		want     bool
		wantErr  error
	}{
		{"owner can read", testUser{ID: "user-123"}, "read", "doc-1", true, nil},
		{"non-owner can read", testUser{ID: "user-456"}, "read", "doc-1", true, nil},
		{"owner can update", testUser{ID: "user-123"}, "update", "doc-1", true, nil},
		{"non-owner cannot update", testUser{ID: "user-456"}, "update", "doc-1", false, nil},
		{"owner can delete", testUser{ID: "user-123"}, "delete", "doc-1", true, nil},
		{"non-owner cannot delete", testUser{ID: "user-456"}, "delete", "doc-1", false, nil},
		{"unknown action denied", testUser{ID: "user-123"}, "archive", "doc-1", false, nil},
		{"loader error passes through", testUser{ID: "user-123"}, "read", "doc-999", false, errDocumentNotFound},
		{"missing object ID", testUser{ID: "user-123"}, "read", "", false, authz.ErrMissingObjectID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, err := engine.Check(context.Background(), tt.user, "document", tt.action, tt.objectID)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if allowed != tt.want {
				t.Errorf("expected %v, got %v", tt.want, allowed)
			}
		})
	}
}

func TestWrapHybrid(t *testing.T) {
	engine := authz.NewEngine[string, string, testUser]()
	engine.Register("document", authz.WrapHybrid(testDocumentPolicy{}, testCollectionPolicy{}, newTestLoader()))

	tests := []struct {
		name     string
		user     testUser
		action   string
		objectID string
		want     bool
	}{
		{"anyone can list (collection)", testUser{Role: "guest"}, "list", "", true},
		{"user can create (collection)", testUser{ID: "user-123"}, "create", "", true},
		{"guest cannot create (collection)", testUser{Role: "guest"}, "create", "", false},
		{"owner can update (object)", testUser{ID: "user-123"}, "update", "doc-1", true},
		{"non-owner cannot update (object)", testUser{ID: "user-456"}, "update", "doc-1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, err := engine.Check(context.Background(), tt.user, "document", tt.action, tt.objectID)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if allowed != tt.want {
				t.Errorf("expected %v, got %v", tt.want, allowed)
			}
		})
	}

	t.Run("loader error passes through", func(t *testing.T) {
		_, err := engine.Check(context.Background(), testUser{ID: "user-123"}, "document", "update", "doc-999")
		if !errors.Is(err, errDocumentNotFound) {
			t.Errorf("expected errDocumentNotFound, got %v", err)
		}
	})

	t.Run("authorizes a loaded object without the loader", func(t *testing.T) {
		doc := testDocument{ID: "doc-9", OwnerID: "user-123"}
		allowed, err := engine.CheckObject(context.Background(), testUser{ID: "user-123"}, "document", "update", doc)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !allowed {
			t.Error("expected allowed to be true")
		}
	})

	t.Run("wrong object type", func(t *testing.T) {
		_, err := engine.CheckObject(context.Background(), testUser{ID: "user-123"}, "document", "update", "not a document")
		if !errors.Is(err, authz.ErrObjectType) {
			t.Errorf("expected ErrObjectType, got %v", err)
		}
	})

	t.Run("panics on nil collection checker", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("expected panic")
			}
		}()
		authz.WrapHybrid(testDocumentPolicy{}, nil, newTestLoader())
	})
}

func TestWrapCollectionOnly(t *testing.T) {
	engine := authz.NewEngine[string, string, testUser]()
	engine.Register("report", authz.WrapCollectionOnly(testCollectionPolicy{}))

	allowed, err := engine.Check(context.Background(), testUser{ID: "user-123"}, "report", "create", "")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !allowed {
		t.Error("expected allowed to be true")
	}

	_, err = engine.Check(context.Background(), testUser{ID: "user-123"}, "report", "read", "report-1")
	if !errors.Is(err, authz.ErrUnexpectedObjectID) {
		t.Errorf("expected ErrUnexpectedObjectID, got %v", err)
	}
}

func TestCheckObject(t *testing.T) {
	engine := authz.NewEngine[string, string, testUser]()
	engine.Register("document", authz.Wrap(testDocumentPolicy{}, newTestLoader()))
	engine.Register("report", authz.WrapCollectionOnly(testCollectionPolicy{}))

	doc := testDocument{ID: "doc-9", OwnerID: "user-123"}

	t.Run("authorizes a loaded object without the loader", func(t *testing.T) {
		allowed, err := engine.CheckObject(context.Background(), testUser{ID: "user-123"}, "document", "update", doc)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !allowed {
			t.Error("expected allowed to be true")
		}

		allowed, err = engine.CheckObject(context.Background(), testUser{ID: "user-456"}, "document", "update", doc)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if allowed {
			t.Error("expected allowed to be false")
		}
	})

	t.Run("wrong object type", func(t *testing.T) {
		_, err := engine.CheckObject(context.Background(), testUser{ID: "user-123"}, "document", "update", "not a document")
		if !errors.Is(err, authz.ErrObjectType) {
			t.Errorf("expected ErrObjectType, got %v", err)
		}
	})

	t.Run("checker without object support", func(t *testing.T) {
		_, err := engine.CheckObject(context.Background(), testUser{ID: "user-123"}, "report", "read", doc)
		if !errors.Is(err, authz.ErrNoObjectChecker) {
			t.Errorf("expected ErrNoObjectChecker, got %v", err)
		}
	})

	t.Run("unknown resource", func(t *testing.T) {
		_, err := engine.CheckObject(context.Background(), testUser{}, "unknown", "read", doc)
		if !errors.Is(err, authz.ErrNoChecker) {
			t.Errorf("expected ErrNoChecker, got %v", err)
		}

		denying := authz.NewEngine[string, string, testUser](authz.WithDenyUnknownResources())
		allowed, err := denying.CheckObject(context.Background(), testUser{}, "unknown", "read", doc)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if allowed {
			t.Error("expected false, got true")
		}
	})

	t.Run("RequireObject returns nil when authorized", func(t *testing.T) {
		err := engine.RequireObject(context.Background(), testUser{ID: "user-123"}, "document", "update", doc)
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("RequireObject returns UnauthorizedError when denied", func(t *testing.T) {
		err := engine.RequireObject(context.Background(), testUser{ID: "user-456"}, "document", "delete", doc)
		if !errors.Is(err, authz.ErrUnauthorized) {
			t.Errorf("expected ErrUnauthorized, got %v", err)
		}
	})

	t.Run("RequireObject propagates checker errors as-is", func(t *testing.T) {
		err := engine.RequireObject(context.Background(), testUser{}, "unknown", "read", doc)
		if !errors.Is(err, authz.ErrNoChecker) {
			t.Errorf("expected ErrNoChecker, got %v", err)
		}
	})
}

func TestHasChecker_Resources(t *testing.T) {
	engine := authz.NewEngine[string, string, testUser]()
	engine.RegisterFunc("doc", adminOnlyChecker)
	engine.RegisterFunc("user", adminOnlyChecker)

	if !engine.HasChecker("doc") {
		t.Error("expected checker to be registered")
	}
	if engine.HasChecker("other") {
		t.Error("expected no checker for unregistered resource")
	}

	resources := engine.Resources()
	if len(resources) != 2 {
		t.Errorf("expected 2 resources, got %d", len(resources))
	}
	found := map[string]bool{}
	for _, r := range resources {
		found[r] = true
	}
	if !found["doc"] || !found["user"] {
		t.Errorf("expected doc and user resources, got %v", resources)
	}
}

func TestDenialLogging(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	engine := authz.NewEngine[string, string, testUser](authz.WithLogger(logger))
	engine.RegisterFunc("document", adminOnlyChecker)

	if err := engine.Require(context.Background(), testUser{Role: "admin"}, "document", "read", "123"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no log on success, got %q", buf.String())
	}

	_ = engine.Require(context.Background(), testUser{ID: "u-1", Role: "guest"}, "document", "read", "123")
	logged := buf.String()
	for _, want := range []string{"authorization denied", "resource=document", "action=read", "object_id=123"} {
		if !strings.Contains(logged, want) {
			t.Errorf("expected log to contain %q, got %q", want, logged)
		}
	}
	if strings.Contains(logged, "u-1") || strings.Contains(logged, "guest") {
		t.Errorf("subject leaked into denial log: %q", logged)
	}
}

// testResource and testAction are opaque identifier types: outside their
// defining package no literal or composite value can be forged, only the
// canonical values below circulate. They also implement fmt.Stringer so that
// denial errors and logs render them readably.
type testResource struct{ name string }

func (r testResource) String() string { return r.name }

type testAction struct{ name string }

func (a testAction) String() string { return a.name }

var (
	resRecipe   = testResource{name: "recipe"}
	actionRead  = testAction{name: "read"}
	actionStart = testAction{name: "start"}
)

func TestOpaqueIdentifierTypes(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	engine := authz.NewEngine[testResource, testAction, testUser](authz.WithLogger(logger))
	engine.RegisterFunc(resRecipe, func(_ context.Context, req authz.Request[testAction, testUser]) (bool, error) {
		return req.Action == actionRead, nil
	})

	if !engine.HasChecker(resRecipe) {
		t.Error("expected checker to be registered for typed resource")
	}

	if err := engine.Require(context.Background(), testUser{}, resRecipe, actionRead, "42"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}

	err := engine.Require(context.Background(), testUser{}, resRecipe, actionStart, "42")
	var uerr *authz.UnauthorizedError
	if !errors.As(err, &uerr) {
		t.Fatalf("expected *UnauthorizedError, got %v", err)
	}
	if uerr.Resource != "recipe" || uerr.Action != "start" || uerr.ObjectID != "42" {
		t.Errorf("expected String rendering of typed identifiers, got %+v", uerr)
	}

	logged := buf.String()
	for _, want := range []string{"resource=recipe", "action=start", "object_id=42"} {
		if !strings.Contains(logged, want) {
			t.Errorf("expected log to contain %q, got %q", want, logged)
		}
	}
}
