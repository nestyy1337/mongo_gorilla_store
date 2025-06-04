package mongo_gorilla_store

import (
	mongoStore "github.com/nestyy1337/mongogorillastore/internal/pkg"
	"go.mongodb.org/mongo-driver/mongo"
)

type MongoStore = mongoStore.MongoStore

func NewMongoStore(coll *mongo.Collection, cookieKey []byte) *mongoStore.MongoStore {
	return mongoStore.NewMongoStore(coll, cookieKey)
}
