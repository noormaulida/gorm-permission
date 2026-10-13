package permission

import (
	"errors"
	"testing"

	"gorm.io/gorm"
)

func TestTxNilReceiver(t *testing.T) {
	var m *Manager
	err := m.tx(func(tx *gorm.DB) error { return nil })
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("got %v", err)
	}
}
