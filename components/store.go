package components

// Session represents a client session.
type Session struct {
	ID           string
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
}

// SessionStore is an interface for session storage backends.
type SessionStore interface {
	Save(*Session) error
	Load(string) (*Session, error)
}
