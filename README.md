<p align="center">
  <img src="https://skillicons.dev/icons?i=go" alt="Go" width="80" />
</p>

<p align="center">
  <img src=".github/gorm-permission.svg" alt="gorm-permission" width="520" />
</p>

<p align="center">
  Spatie Laravel Permission–compatible roles and permissions for GORM.
</p>

<p align="center">
  <a href="https://github.com/noormaulida/gorm-permission/actions/workflows/go.yml">
    <img src="https://github.com/noormaulida/gorm-permission/actions/workflows/go.yml/badge.svg" alt="Go Tests" />
  </a>
  <a href="https://codecov.io/gh/noormaulida/gorm-permission">
    <img src="https://codecov.io/gh/noormaulida/gorm-permission/graph/badge.svg" alt="codecov" />
  </a>
  <a href="https://pkg.go.dev/github.com/noormaulida/gorm-permission">
    <img src="https://pkg.go.dev/badge/github.com/noormaulida/gorm-permission.svg" alt="Go Reference" />
  </a>
  <a href="https://github.com/noormaulida/gorm-permission/blob/master/LICENSE">
    <img src="https://img.shields.io/github/license/noormaulida/gorm-permission" alt="License" />
  </a>
</p>

## Features

- Spatie-compatible tables: `permissions`, `roles`, `model_has_roles`, `model_has_permissions`, `role_has_permissions`
- Guards (for example `cms` / `web`)
- Assign / remove / sync roles and direct permissions
- `HasPermissionTo` checks direct permissions **and** permissions via roles
- Framework-agnostic core (wire Gin/Echo/etc. in your app)
- Go **1.22+**

## Installation

```bash
go get github.com/noormaulida/gorm-permission@latest
```

## Setup

```go
db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
if err != nil {
    return err
}

if err := permission.Migrate(db); err != nil {
    return err
}

perm := permission.New(db, permission.WithDefaultGuard("cms"))
```

`Migrate` is optional when the database already uses Spatie Laravel Permission migrations.

## Authorizable model

Implement `Authorizable` on the actor model. Use a stable morph alias when sharing a Laravel database:

```go
type Admin struct {
    ID    uint64
    Name  string
    Email string
}

func (a Admin) PermissionModelID() uint64   { return a.ID }
func (a Admin) PermissionModelType() string { return "admins" }
func (a Admin) PermissionGuardName() string { return "cms" }
```

`PermissionGuardName` is optional; without it the manager default guard is used.

## Quick start

```go
role, _ := perm.FindOrCreateRole("super-administrator")
_, _ = perm.FindOrCreatePermission("cms.admins.view")
_, _ = perm.FindOrCreatePermission("cms.admins.update")

_ = perm.GivePermissionToRole(role, "cms.admins.view", "cms.admins.update")
_ = perm.AssignRole(admin, "super-administrator")

ok, _ := perm.HasPermissionTo(admin, "cms.admins.view") // true via role
ok, _ = perm.Can(admin, "cms.admins.update")            // alias of HasPermissionTo
ok, _ = perm.HasRole(admin, "super-administrator")
```

### Direct permissions

```go
_ = perm.GivePermissionTo(admin, "cms.pages.view")
_ = perm.RevokePermissionTo(admin, "cms.pages.view")
_ = perm.SyncPermissions(admin, "cms.pages.update")
```

### Roles

```go
_ = perm.AssignRole(admin, "editor", "writer")
_ = perm.RemoveRole(admin, "writer")
_ = perm.SyncRoles(admin, "editor")
```

## Gin middleware snippet

This package stays framework-agnostic. Copy a small middleware into your app:

```go
func RequirePermission(perm *permission.Manager, name string) gin.HandlerFunc {
    return func(c *gin.Context) {
        admin, ok := currentAdmin(c) // your auth → permission.Authorizable
        if !ok {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
            return
        }
        allowed, err := perm.HasPermissionTo(admin, name)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
            return
        }
        if !allowed {
            c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
            return
        }
        c.Next()
    }
}

// r.GET("/cms/admins", RequirePermission(perm, "cms.admins.view"), listAdmins)
```

The same pattern works with `HasRole` / `HasAnyPermission`.

## Spatie compatibility notes

| Concern | Guidance |
|---------|----------|
| Table / columns | Same defaults as Spatie |
| `model_type` | Prefer a morph map alias (`admins`) shared with Laravel |
| `model_id` | Numeric `unsigned big integer` (Spatie default) |
| Unique `(name, guard_name)` | Enforced by `Migrate` (same as Spatie). Existing Spatie DBs already have this index |
| Foreign keys | Pivot rows cascade-delete when a role/permission is removed (Spatie-compatible) |

## Minimum Go version

Go **1.22** or higher.

## License

MIT License
