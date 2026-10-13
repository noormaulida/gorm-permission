package permission

import "gorm.io/gorm"

// Manager is the entry point for role and permission operations.
type Manager struct {
	db           *gorm.DB
	defaultGuard string
}

// Option configures a Manager.
type Option func(*Manager)

// WithDefaultGuard sets the guard used when a model does not implement
// GuardedAuthorizable. Spatie / SuitCMS typically use "cms" or "web".
func WithDefaultGuard(guard string) Option {
	return func(m *Manager) {
		if guard != "" {
			m.defaultGuard = guard
		}
	}
}

// New creates a Manager bound to db.
func New(db *gorm.DB, opts ...Option) *Manager {
	m := &Manager{
		db:           db,
		defaultGuard: "web",
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// DB exposes the underlying GORM handle (useful in tests and transactions).
func (m *Manager) DB() *gorm.DB {
	return m.db
}

// DefaultGuard returns the configured default guard name.
func (m *Manager) DefaultGuard() string {
	return m.defaultGuard
}

func (m *Manager) guardOrDefault(guard string) string {
	if guard != "" {
		return guard
	}
	return m.defaultGuard
}

func (m *Manager) tx(fn func(tx *gorm.DB) error) error {
	if m == nil || m.db == nil {
		return ErrInvalidArgument
	}
	return m.db.Transaction(fn)
}
