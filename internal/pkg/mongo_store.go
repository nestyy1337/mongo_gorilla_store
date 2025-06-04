package pkg

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoStore struct {
	coll         *mongo.Collection
	codec        *securecookie.SecureCookie
	maxAge       int
	cookieName   string
	cleanupAfter time.Duration
}

type SessionRecord struct {
	ID       string    `bson:"_id"`
	Data     string    `bson:"data"`
	Modified time.Time `bson:"modified"`
}

func NewMongoStore(coll *mongo.Collection, cookiekey []byte) *MongoStore {
	codec := securecookie.New(cookiekey, cookiekey)
	return &MongoStore{
		coll:         coll,
		codec:        codec,
		maxAge:       7 * 24 * 3600,
		cookieName:   "session-id",
		cleanupAfter: 7 * 24 * time.Hour,
	}
}

func (m *MongoStore) MaxAge(age int) {
	m.maxAge = age
}

func (m *MongoStore) CookieName(name string) {
	m.cookieName = name
}

func (m *MongoStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(m, name)
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   m.maxAge,
		Secure:   false,
		HttpOnly: false,
	}
	session.IsNew = true

	c, err := r.Cookie(m.cookieName)
	if err != nil {
		return session, nil
	}

	var sessionID string
	if err := m.codec.Decode(m.cookieName, c.Value, &sessionID); err != nil {
		return session, err
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var record SessionRecord
	filter := bson.M{"_id": sessionID}
	if err := m.coll.FindOne(ctx, filter).Decode(&record); err != nil {
		if err == mongo.ErrNoDocuments {
			session.ID = sessionID
			return session, nil
		}
		return session, err
	}
	var flat map[string]any
	if err := json.Unmarshal([]byte(record.Data), &flat); err != nil {
		return session, err
	}

	values := make(map[any]any, len(flat))
	for k, v := range flat {
		maps.Copy(values, map[any]any{k: v})
	}

	session.ID = sessionID
	session.Values = values
	session.IsNew = false
	return session, nil
}

func (m *MongoStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(m, name)
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   m.maxAge,
		HttpOnly: true,
	}
	session.ID = ""
	session.IsNew = true
	return session, nil
}

func (m *MongoStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if session.Options.MaxAge <= 0 {
		http.SetCookie(w, &http.Cookie{
			Name:     m.cookieName,
			Value:    "",
			Path:     session.Options.Path,
			MaxAge:   -1,
			HttpOnly: session.Options.HttpOnly,
		})
		if session.ID != "" {
			_, _ = m.coll.DeleteOne(ctx, bson.M{"_id": session.ID})
		}
		return nil
	}

	if session.ID == "" {
		rawKey := securecookie.GenerateRandomKey(32)
		session.ID = hex.EncodeToString(rawKey)
		session.IsNew = true
	}

	flat := make(map[string]any, len(session.Values))
	for rawKey, rawVal := range session.Values {
		k, ok := rawKey.(string)
		if !ok {
			continue
		}
		flat[k] = rawVal
	}

	dataBytes, err := json.Marshal(flat)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	upd := bson.M{
		"$set": bson.M{
			"data":     string(dataBytes),
			"modified": now,
		},
	}
	fmt.Println("Session ID:", session.ID)
	fmt.Println("Session Data:", string(dataBytes))

	opts := options.Update().SetUpsert(true)
	if _, err := m.coll.UpdateByID(ctx, session.ID, upd, opts); err != nil {
		return err
	}

	encoded, err := m.codec.Encode(m.cookieName, session.ID)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    encoded,
		Path:     session.Options.Path,
		MaxAge:   session.Options.MaxAge,
		HttpOnly: session.Options.HttpOnly,
		Secure:   false,
	})

	return nil
}
