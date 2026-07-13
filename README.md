# authz

A small, application-agnostic **authorization** library for Go, built on the
classic *subject–action–object* model of access control: every check answers
the question

> may this **subject** perform this **action** on this **object**?

You write the answers ("policies") as plain Go code; `authz` gives you a
uniform way to register them, invoke them, and turn denials into errors and
log records.

What this library is **not**:

- It is not authentication. It never verifies who the subject is — that
  happened earlier, in your session/token middleware. `authz` starts *after*
  you already have a trusted subject value in hand.
- It is not a rule engine or a policy language. There is no DSL, no database
  of permissions, no roles framework. A policy is a Go function; if your
  application has roles, your policy reads them from your own user type.

Requires Go ≥ 1.23 (generics with method-based inference, `log/slog`).


## Core concepts

| Term         | In the API                          | Meaning                                                                      |
|--------------|-------------------------------------|------------------------------------------------------------------------------|
| **Subject**  | the type parameter `S`              | Whoever is acting: your user/principal struct. Chosen by *your* application. |
| **Resource** | the type parameter `R` (comparable) | The *kind* of thing being accessed. Used to dispatch to the right policy.    |
| **Action**   | the type parameter `A` (comparable) | What the subject wants to do.                                                |
| **Object**   | `ObjectID string` or a loaded value | The *specific* thing being accessed: recipe #5, document `"doc-123"`.        |

All three are chosen by *your* application and are completely opaque to the
library: it carries them from the call site to your policies, which receive
them **already typed** — no `interface{}`, no type assertions. The subject is
never inspected and never logged; `R` and `A` are only rendered (with
`fmt.Sprint`) in denial errors and log records. Plain `string` works for both
`R` and `A`; see [Choosing `R` and `A`](#choosing-r-and-a-how-strict-do-you-want-to-be)
for stricter options.

## Quick start

```go
package main

import (
  "context"

  "github.com/4Sigma/authz"
)

type User struct {
  ID   int64
  Role string
}

func main() {
  // Type parameters: resource type, action type, subject type.
  engine := authz.NewEngine[string, string, *User]()

  // The simplest possible policy: a function.
  engine.RegisterFunc("report", func(ctx context.Context, req authz.Request[string, *User]) (bool, error) {
    return req.Subject.Role == "admin", nil
  })

  user := &User{ID: 42, Role: "admin"}
  if err := engine.Require(context.Background(), user, "report", "read", "monthly-2026-07"); err != nil {
    // err is an *authz.UnauthorizedError (matches errors.Is(err, authz.ErrUnauthorized))
    panic(err)
  }
  // authorized — proceed
}
```

`Require` returns `nil` when allowed and an `*UnauthorizedError` when denied.
If you prefer to branch on a boolean, use `Check`, which returns
`(bool, error)` and reserves the error for *failures* (unknown resource,
loader error), never for denials.

## Choosing `R` and `A`: how strict do you want to be?

The resource and action types only need to satisfy Go's built-in
`comparable` constraint — "usable with `==`" — which is what lets the engine
key its internal map by `R` and your policies `switch` on `A`. That leaves
the strictness up to you, and there is a ladder:

1. **Plain `string`** — zero ceremony, zero protection. Any typo compiles and
   fails at runtime (loudly, see [below](#unknown-resources-fail-loud-or-fail-closed),
   but still at runtime).

2. **Named string types** (`type Action string` with constants) —
   documentation, *not* enforcement. Go's untyped string literals convert
   implicitly, so `engine.Require(ctx, u, resRecipe, "strat", id)` still
   compiles. You get autocompletion and grep-ability; you do not get a
   compile error on a typo.

3. **Opaque struct types** — literal-proof. Define them once, in one
   canonical package of your application:

   ```go
   package appz

   type Action struct{ name string }

   func (a Action) String() string { return a.name }

   var (
     ActionRead  = Action{name: "read"}
     ActionStart = Action{name: "start"}
   )
   ```

   Outside `appz` nobody can forge an `Action`: string literals don't
   convert, the composite literal `Action{...}` doesn't compile (unexported
   field), and a typo like `appz.ActionStrat` is an undeclared identifier.
   The canonical values are the only ones in circulation.

Notes on opaque types:

- A struct with only comparable fields **is** `comparable` — no method is
  required for that. The `String()` method above is unrelated: it is
  `fmt.Stringer`, and it is what makes denial errors and log records render
  the value as `start` instead of `{start}` (they use `fmt.Sprint`).
- The zero value (`Action{}`) can still be constructed, but it is harmless:
  it matches no `case` in any policy, so it is denied like every unknown
  action (fail closed).

## Type-safe policies: `ResourceChecker` + `ObjectLoader` + `Wrap`

For real resources you usually need the object itself to decide (ownership
checks, state checks). Implement two small interfaces:

```go
// The policy: pure decision logic, fully typed.
type DocumentPolicy struct{}

func (DocumentPolicy) Can(ctx context.Context, user *User, action string, doc Document) (bool, error) {
  switch action {
  case "read":
    return doc.IsPublic || doc.OwnerID == user.ID, nil
  case "update", "delete":
    return doc.OwnerID == user.ID, nil
  }
  return false, nil // unknown action → deny
}

// The loader: fetches the object behind a Request's ObjectID.
type DocumentLoader struct{ repo *DocumentRepo }

func (l DocumentLoader) Load(ctx context.Context, id string) (Document, error) {
  docID, err := strconv.ParseInt(id, 10, 64)
  if err != nil {
    return Document{}, err
  }
  return l.repo.GetByID(ctx, docID)
}
```

and register them together:

```go
engine.Register("document", authz.Wrap(DocumentPolicy{}, DocumentLoader{repo}))
```

Now `engine.Require(ctx, user, "document", "update", "17")` loads document 17
through your loader and asks your policy. Loader errors (e.g. *not found*)
pass through **unchanged**, so the caller can still tell a missing object
(→ HTTP 404) apart from a denial (→ HTTP 403).

> **Why is `ObjectID` a string?** Because that is how identifiers arrive at an
> application's boundary: URL path segments, message fields, form values. The
> loader is exactly the place where your application converts it (to `int64`,
> UUID, ...). This keeps the engine usable from generic middleware that only
> sees the URL.

If you don't want to define types, `WrapFunc` accepts plain functions:

```go
engine.Register("document", authz.WrapFunc(
  func(ctx context.Context, user *User, action string, doc Document) (bool, error) {
    return doc.OwnerID == user.ID, nil
  },
  loader.Load, // any func(ctx, string) (Document, error)
))
```

## Collection-level actions: `WrapHybrid`, `WrapCollectionOnly`

Actions like `create` and `list` have no object yet. They are expressed as
requests with an **empty `ObjectID`** and are decided by a
`CollectionChecker`:

```go
type DocumentCollectionPolicy struct{}

func (DocumentCollectionPolicy) CanCollection(ctx context.Context, user *User, action string) (bool, error) {
  switch action {
  case "list":
    return true, nil
  case "create":
    return user.Role != "guest", nil
  }
  return false, nil
}
```

Register both levels with `WrapHybrid`:

```go
engine.Register("document", authz.WrapHybrid(
  DocumentPolicy{},           // object-level actions (ObjectID != "")
  DocumentCollectionPolicy{}, // collection-level actions (ObjectID == "")
  DocumentLoader{repo},
))

engine.Require(ctx, user, "document", "create", "") // → collection policy
engine.Require(ctx, user, "document", "update", "17") // → loader + object policy
```

For resources that *only* have collection-level actions, use
`authz.WrapCollectionOnly(policy)`.

Mismatches are reported honestly instead of being silently denied:

- an object-level request reaching a checker with no loader path returns
  `ErrMissingObjectID` / `ErrUnexpectedObjectID`;
- `WrapHybrid` **panics at wiring time** if you pass a `nil` collection
  checker — a misconfigured resource should fail at startup, not at request
  time.

## Skipping the loader: `CheckObject` / `RequireObject`

Inside a service layer you typically *already have* the object — you loaded
it to work on it. Re-loading it just to authorize would be wasteful, so the
engine can check a loaded value directly:

```go
func (s *DocumentService) Update(ctx context.Context, user *User, id int64, patch DocumentPatch) error {
  doc, err := s.repo.GetByID(ctx, id)
  if err != nil {
    return err
  }
  if err := s.authz.RequireObject(ctx, user, "document", "update", doc); err != nil {
    return err // *authz.UnauthorizedError
  }
  // ... apply patch
}
```

This works with every checker built by `Wrap`, `WrapFunc` and `WrapHybrid`
(they all implement the `ObjectChecker` interface). Passing a value of the
wrong type returns `ErrObjectType`; using it on a checker registered with
`RegisterFunc` or `WrapCollectionOnly` returns `ErrNoObjectChecker`.

## Handling denials

`Require`/`RequireObject` return an `*UnauthorizedError` carrying the request
context, so a transport layer can build a meaningful response:

```go
err := engine.Require(ctx, user, "document", "update", "17")

var denied *authz.UnauthorizedError
switch {
case err == nil:
  // allowed
case errors.As(err, &denied):
  // denied.Resource == "document", denied.Action == "update", denied.ObjectID == "17"
  http.Error(w, denied.Error(), http.StatusForbidden)
default:
  // infrastructure failure: unknown resource, loader error, ...
  http.Error(w, "internal error", http.StatusInternalServerError)
}
```

`errors.Is(err, authz.ErrUnauthorized)` also matches, for callers that don't
need the details.

`UnauthorizedError.Resource` and `.Action` are always `string`, whatever `R`
and `A` are: the engine renders the typed values with `fmt.Sprint` when it
builds the error. Give your identifier types a `String()` method to control
that rendering.

### Error reference

| Error                   | Returned by                | Meaning                                                            |
|-------------------------|----------------------------|--------------------------------------------------------------------|
| `*UnauthorizedError`    | `Require`, `RequireObject` | The policy said no. Matches `errors.Is(_, ErrUnauthorized)`.       |
| `ErrNoChecker`          | all check methods          | No checker registered for that resource kind (see below).          |
| `ErrMissingObjectID`    | `Wrap`-built checkers      | Object-level checker got a request with an empty `ObjectID`.       |
| `ErrUnexpectedObjectID` | `WrapCollectionOnly`       | Collection-only checker got a request with an `ObjectID`.          |
| `ErrNoObjectChecker`    | `CheckObject`/`RequireObject` | The registered checker cannot take already-loaded objects.      |
| `ErrObjectType`         | `CheckObject`/`RequireObject` | The loaded object is not the type the checker handles.          |
| *(your loader's errors)*| `Check`/`Require`          | Passed through unchanged — e.g. map "not found" to HTTP 404.       |

## Unknown resources: fail loud or fail closed

By default, checking a resource kind nobody registered returns
`ErrNoChecker` — a loud failure that catches typos and missing wiring during
development.

For production you may prefer *fail closed*: treat unknown resources as plain
denials.

```go
engine := authz.NewEngine[string, string, *User](authz.WithDenyUnknownResources())
```

There is deliberately **no fail-open mode** (unknown → allow): in an
authorization library that is a foot-gun — one typo in a resource name and an
endpoint is silently open to everyone.

You can assert your wiring at startup:

```go
for _, r := range []string{"document", "report", "recipe"} {
  if !engine.HasChecker(r) {
    log.Fatalf("authz: no policy registered for %q", r)
  }
}
```

## Logging denials

Pass a `*slog.Logger` to have every denial from `Require`/`RequireObject`
logged at `Warn` level with `resource`, `action` and `object_id` attributes.
The subject is **never** logged (it is your user object; keeping it out of
the logs is the library's job, deciding what *is* loggable is yours).

```go
engine := authz.NewEngine[string, string, *User](authz.WithLogger(slog.Default()))
```

### With zerolog

Applications that log with [zerolog](https://github.com/rs/zerolog) can
bridge their existing logger through the `zerologadapter` subpackage, which
wraps a `*zerolog.Logger` as a `slog.Handler`:

```go
import (
  "log/slog"

  "github.com/4Sigma/authz"
  "github.com/4Sigma/authz/zerologadapter"
)

engine := authz.NewEngine[string, string, *User](
  authz.WithLogger(slog.New(zerologadapter.Handler(&zlogger))),
)
```

The adapter lives in its own package so that applications not using zerolog
never link it. Timestamps come from the wrapped zerolog logger's own
configuration (e.g. `.Timestamp()`); slog groups are flattened into
dot-separated keys (`req.id`).

## Configuration

`NewEngine` takes zero or more `ConfigModifier` values — functions that each
apply one setting; `NewEngine` folds them, in order, over the default
configuration:

| Modifier                        | Effect                                                       |
|---------------------------------|--------------------------------------------------------------|
| `WithDenyUnknownResources()`    | Unknown resource kinds → plain denial instead of `ErrNoChecker`. |
| `WithLogger(l *slog.Logger)`    | Log denials from `Require`/`RequireObject` at `Warn` level.  |

Defaults (no modifiers): unknown resources are loud errors, nothing is
logged.

## Engine API summary

| Method                                            | Use when                                                        |
|---------------------------------------------------|------------------------------------------------------------------|
| `Register(resource, checker)`                     | Wiring a policy at startup (replaces any previous one).          |
| `RegisterFunc(resource, fn)`                      | Same, for a plain function policy.                               |
| `Check(ctx, subject, resource, action, objectID)` | You want a `bool` and will branch yourself (e.g. to hide a button). |
| `Require(ctx, subject, resource, action, objectID)` | You want denial-as-error (the common case in handlers).        |
| `CheckObject(ctx, subject, resource, action, obj)`  | Same as `Check`, but the object is already loaded.             |
| `RequireObject(ctx, subject, resource, action, obj)`| Same as `Require`, but the object is already loaded.           |
| `HasChecker(resource)` / `Resources()`            | Boot-time wiring assertions and diagnostics.                     |

All methods are safe for concurrent use.

## Design notes

- **Subject, resource and action are type parameters, not `any`/`string`.**
  Your policies receive your user type already typed, and with opaque `R`/`A`
  types a forged identifier is a compile error, not a runtime surprise. How
  strict to be is the application's choice, not the library's.
- **One type-parameter order everywhere**: identifier types first (`R`, then
  `A`), then the subject `S`, then the object type `T` — e.g.
  `Engine[R, A, S]`, `Request[A, S]`, `ResourceChecker[A, S, T]`. In practice
  you spell them out only at `NewEngine`; everything else is inferred.
- **Denials are not errors in `Check`.** `Check` returns `(false, nil)` for
  "no"; errors are reserved for infrastructure problems. `Require` is the
  convenience that converts "no" into `*UnauthorizedError`.
- **Loader errors are yours.** The library does not define what "not found"
  means; whatever your loader returns is what the caller sees.
- **No policy storage, no caching.** Policies run on every check. If a policy
  is expensive, caching belongs inside your loader or policy, where you know
  the invalidation rules.
- **Zero dependencies** in the core package (stdlib only). The optional
  `zerologadapter` subpackage is the only place depending on zerolog.
