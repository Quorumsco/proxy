package components

import (
	"fmt"
	"strconv"

	"gopkg.in/redis.v3"
)

// RedisStore use Redis to store Sessions.
// It satisfies SessionStore.
type RedisStore struct {
	client *redis.Client
}

// NewRedisStore initialize a new RedisStore.
func NewRedisStore(client *redis.Client) *RedisStore {
	return &RedisStore{
		client: client,
	}
}

// Save session in the Redis endpoint.
func (r *RedisStore) Save(s *Session) error {
	r.client.HMSet(s.ID,
		"expires_in", strconv.Itoa(s.ExpiresIn),
		"access_token", s.AccessToken,
		"refresh_token", s.RefreshToken).Result()
	return nil
}

// Load a previously saved session or error.
func (r *RedisStore) Load(id string) (*Session, error) {
	exist, err := r.client.Exists(id).Result()
	if err != nil {
		return nil, err
	} else if !exist {
		return nil, fmt.Errorf("No such key %s", id)
	}
	sMap, err := r.client.HGetAllMap(id).Result()
	if err != nil {
		return nil, err
	}
	expiresIn, _ := strconv.Atoi(sMap["expires_in"])
	return &Session{
		ID:           id,
		ExpiresIn:    expiresIn,
		AccessToken:  sMap["access_token"],
		RefreshToken: sMap["refresh_token"],
	}, nil
}
