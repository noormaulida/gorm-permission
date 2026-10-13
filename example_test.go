package permission_test

import (
	"fmt"

	permission "github.com/noormaulida/gorm-permission"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type exampleAdmin struct {
	ID uint64
}

func (a exampleAdmin) PermissionModelID() uint64   { return a.ID }
func (a exampleAdmin) PermissionModelType() string { return "admins" }
func (a exampleAdmin) PermissionGuardName() string { return "cms" }

func ExampleManager_HasPermissionTo() {
	db, err := gorm.Open(sqlite.Open("file:example?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	_ = permission.Migrate(db)
	perm := permission.New(db, permission.WithDefaultGuard("cms"))

	role, _ := perm.FindOrCreateRole("super-administrator")
	_, _ = perm.FindOrCreatePermission("cms.admins.view")
	_ = perm.GivePermissionToRole(role, "cms.admins.view")

	admin := exampleAdmin{ID: 1}
	_ = perm.AssignRole(admin, "super-administrator")

	ok, _ := perm.HasPermissionTo(admin, "cms.admins.view")
	fmt.Println(ok)
	// Output: true
}
