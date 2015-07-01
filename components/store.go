package components

type Session struct {
	Cookie       string
	AccessToken  string
	RefreshToken string
}

type SessionStore interface {
	Save(*Session)
	Load() *Session
}
