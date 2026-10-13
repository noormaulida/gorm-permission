package permission_test

import (
	"errors"
	"testing"

	permission "github.com/noormaulida/gorm-permission"
)

type bareModel struct {
	id  uint64
	typ string
}

func (b bareModel) PermissionModelID() uint64   { return b.id }
func (b bareModel) PermissionModelType() string { return b.typ }

type emptyGuardModel struct {
	id uint64
}

func (e emptyGuardModel) PermissionModelID() uint64     { return e.id }
func (e emptyGuardModel) PermissionModelType() string   { return "admins" }
func (e emptyGuardModel) PermissionGuardName() string   { return "" }

func TestModelFrom(t *testing.T) {
	_, perm := setup(t)
	if _, err := perm.FindOrCreateRole("editor"); err != nil {
		t.Fatal(err)
	}
	model := permission.ModelFrom(7, "admins")
	// ModelFrom has no guard; manager default "cms" is used.
	if err := perm.AssignRole(model, "editor"); err != nil {
		t.Fatalf("AssignRole via ModelFrom: %v", err)
	}
	ok, err := perm.HasRole(model, "editor")
	if err != nil || !ok {
		t.Fatalf("HasRole: ok=%v err=%v", ok, err)
	}
}

func TestResolveModelValidation(t *testing.T) {
	_, perm := setup(t)

	if err := perm.AssignRole(nil, "editor"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("nil model: got %v", err)
	}
	if err := perm.AssignRole(Admin{ID: 0, Name: "x"}, "editor"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("zero id: got %v", err)
	}
	if err := perm.AssignRole(bareModel{id: 1, typ: ""}, "editor"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("empty type: got %v", err)
	}

	if _, err := perm.FindOrCreateRole("editor"); err != nil {
		t.Fatal(err)
	}
	// Empty PermissionGuardName falls back to manager default.
	if err := perm.AssignRole(emptyGuardModel{id: 3}, "editor"); err != nil {
		t.Fatalf("empty guard model: %v", err)
	}
}

func TestPrimaryKeyIDVariants(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		_, err := permission.PrimaryKeyID(nil)
		if !errors.Is(err, permission.ErrInvalidArgument) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("nil pointer", func(t *testing.T) {
		var a *Admin
		_, err := permission.PrimaryKeyID(a)
		if !errors.Is(err, permission.ErrInvalidArgument) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("non-struct", func(t *testing.T) {
		_, err := permission.PrimaryKeyID(42)
		if !errors.Is(err, permission.ErrInvalidArgument) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no ID field", func(t *testing.T) {
		_, err := permission.PrimaryKeyID(struct{ Name string }{Name: "x"})
		if !errors.Is(err, permission.ErrInvalidArgument) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("uint pointer", func(t *testing.T) {
		a := &Admin{ID: 5}
		id, err := permission.PrimaryKeyID(a)
		if err != nil || id != 5 {
			t.Fatalf("id=%d err=%v", id, err)
		}
	})
	t.Run("int id", func(t *testing.T) {
		type row struct{ ID int64 }
		id, err := permission.PrimaryKeyID(row{ID: 11})
		if err != nil || id != 11 {
			t.Fatalf("id=%d err=%v", id, err)
		}
	})
	t.Run("gorm primaryKey tag", func(t *testing.T) {
		type row struct {
			UserID uint64 `gorm:"primaryKey"`
			Name   string
		}
		id, err := permission.PrimaryKeyID(row{UserID: 42, Name: "x"})
		if err != nil || id != 42 {
			t.Fatalf("id=%d err=%v", id, err)
		}
	})
	t.Run("embedded primaryKey", func(t *testing.T) {
		type base struct {
			BaseID uint64 `gorm:"primaryKey;autoIncrement"`
		}
		type row struct {
			base
			Name string
		}
		id, err := permission.PrimaryKeyID(row{base: base{BaseID: 7}, Name: "x"})
		if err != nil || id != 7 {
			t.Fatalf("id=%d err=%v", id, err)
		}
	})
	t.Run("embedded ID fallback", func(t *testing.T) {
		type base struct{ ID uint64 }
		type row struct {
			base
			Name string
		}
		id, err := permission.PrimaryKeyID(row{base: base{ID: 3}, Name: "x"})
		if err != nil || id != 3 {
			t.Fatalf("id=%d err=%v", id, err)
		}
	})
	t.Run("skip embed without ID then use ID", func(t *testing.T) {
		type embed struct{ Name string }
		type row struct {
			embed
			ID uint64
		}
		id, err := permission.PrimaryKeyID(row{ID: 4})
		if err != nil || id != 4 {
			t.Fatalf("id=%d err=%v", id, err)
		}
	})
	t.Run("anonymous without pk then tagged", func(t *testing.T) {
		type embed struct{ Name string }
		type row struct {
			embed
			UserID uint64 `gorm:"primaryKey"`
		}
		id, err := permission.PrimaryKeyID(row{UserID: 8})
		if err != nil || id != 8 {
			t.Fatalf("id=%d err=%v", id, err)
		}
	})
	t.Run("unexported primaryKey ignored", func(t *testing.T) {
		type row struct {
			userID uint64 `gorm:"primaryKey"`
			ID     uint64
		}
		id, err := permission.PrimaryKeyID(row{userID: 1, ID: 5})
		if err != nil || id != 5 {
			t.Fatalf("id=%d err=%v", id, err)
		}
	})
	t.Run("primaryKey preferred over ID", func(t *testing.T) {
		type row struct {
			ID     uint64
			UserID uint64 `gorm:"primaryKey"`
		}
		id, err := permission.PrimaryKeyID(row{ID: 1, UserID: 99})
		if err != nil || id != 99 {
			t.Fatalf("id=%d err=%v", id, err)
		}
	})
	t.Run("non-positive int", func(t *testing.T) {
		type row struct{ ID int }
		_, err := permission.PrimaryKeyID(row{ID: 0})
		if !errors.Is(err, permission.ErrInvalidArgument) {
			t.Fatalf("got %v", err)
		}
		_, err = permission.PrimaryKeyID(row{ID: -1})
		if !errors.Is(err, permission.ErrInvalidArgument) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("unsupported id type", func(t *testing.T) {
		type row struct{ ID string }
		_, err := permission.PrimaryKeyID(row{ID: "1"})
		if !errors.Is(err, permission.ErrInvalidArgument) {
			t.Fatalf("got %v", err)
		}
	})
}
