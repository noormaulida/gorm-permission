package permission_test

import (
	"errors"
	"testing"

	permission "github.com/noormaulida/gorm-permission"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestNewAndOptions(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:manager_opts?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	perm := permission.New(db)
	if perm.DefaultGuard() != "web" {
		t.Fatalf("default guard: got %q", perm.DefaultGuard())
	}
	if perm.DB() != db {
		t.Fatal("DB() should return underlying handle")
	}

	perm = permission.New(db, permission.WithDefaultGuard("cms"), permission.WithDefaultGuard(""))
	if perm.DefaultGuard() != "cms" {
		t.Fatalf("empty WithDefaultGuard should keep prior value, got %q", perm.DefaultGuard())
	}
}

func TestMigrateNilDB(t *testing.T) {
	if err := permission.Migrate(nil); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
}
