/*
Package authz is a small, application-agnostic authorization layer built on
the classic subject–action–object model of access control: "may this subject
perform this action on this object?".

All three sides of the question are type parameters chosen by the
application. The subject type S is typically its user or principal struct;
the resource type R and the action type A are comparable identifier types —
plain strings work, opaque struct types make forged literals impossible (see
the README, "Choosing R and A"). The package never inspects any of them: it
only carries them from the call site to the policies, which receive them
already typed.

Basic usage, with strings for both identifier types:

	engine := authz.NewEngine[string, string, *User]()
	engine.RegisterFunc("document", func(ctx context.Context, req authz.Request[string, *User]) (bool, error) {
		return req.Subject.Role == "admin", nil
	})
	err := engine.Require(ctx, user, "document", "read", "doc-123")

Type-safe policies with ResourceChecker and an ObjectLoader that fetches the
object behind a Request's ObjectID:

	type DocumentPolicy struct{}

	func (DocumentPolicy) Can(ctx context.Context, user *User, action string, doc Document) (bool, error) {
		switch action {
		case "read":
			return doc.IsPublic || doc.OwnerID == user.ID, nil
		case "update", "delete":
			return doc.OwnerID == user.ID, nil
		}
		return false, nil
	}

	engine.Register("document", authz.Wrap(DocumentPolicy{}, documentLoader))

For resources that also have collection-level actions (create, list, ...) use
WrapHybrid; for resources that only have collection-level actions use
WrapCollectionOnly.

When the caller has already loaded the object (the common case inside a
service layer), Engine.CheckObject and Engine.RequireObject authorize it
directly, skipping the ObjectLoader round-trip. Every checker built with Wrap
or WrapHybrid supports this.

Denials returned by Require and RequireObject match
errors.Is(err, ErrUnauthorized) and carry the request context as an
*UnauthorizedError. Pass a *slog.Logger with WithLogger to have denials
logged; applications that log with zerolog can bridge it through the
zerologadapter subpackage.

Throughout the package, generic types share one parameter order: identifier
types first (R, then A), then the subject S, then the object type T.
*/
package authz
