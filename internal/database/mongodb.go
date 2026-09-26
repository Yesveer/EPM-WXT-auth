package database

import (
	"context"
	"fmt"
	"time"

	"github.com/vsay/vsay-auth/internal/config"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

type MongoDB struct {
	client   *mongo.Client
	database *mongo.Database
	logger   *zap.Logger
}

func NewMongoDB(cfg *config.Config, logger *zap.Logger) (*MongoDB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect to MongoDB
	clientOptions := options.Client().ApplyURI(cfg.MongoURI)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Ping to verify connection
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	database := client.Database(cfg.MongoDatabase)

	db := &MongoDB{
		client:   client,
		database: database,
		logger:   logger,
	}

	// Create indexes
	if err := db.createIndexes(ctx); err != nil {
		return nil, fmt.Errorf("failed to create indexes: %w", err)
	}

	logger.Info("Connected to MongoDB",
		zap.String("database", cfg.MongoDatabase))

	return db, nil
}

func (db *MongoDB) createIndexes(ctx context.Context) error {
	// Users collection indexes
	usersCol := db.database.Collection("users")
	_, err := usersCol.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "username", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "email", Value: 1}},
		},
		{
			Keys:    bson.D{{Key: "keycloak_id", Value: 1}},
			Options: options.Index().SetUnique(true).SetSparse(true),
		},
		{
			Keys: bson.D{{Key: "tenant_id", Value: 1}},
		},
		{
			Keys:    bson.D{{Key: "api_key", Value: 1}},
			Options: options.Index().SetSparse(true),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create users indexes: %w", err)
	}

	// Organizations collection indexes
	orgsCol := db.database.Collection("organizations")
	_, err = orgsCol.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "name", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "keycloak_realm", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create organizations indexes: %w", err)
	}

	// Groups collection indexes
	groupsCol := db.database.Collection("groups")
	_, err = groupsCol.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "tenant_id", Value: 1},
				{Key: "name", Value: 1},
			},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "keycloak_id", Value: 1}},
			Options: options.Index().SetSparse(true),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create groups indexes: %w", err)
	}

	// Audit logs collection indexes
	auditCol := db.database.Collection("audit_logs")
	_, err = auditCol.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "user_id", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "tenant_id", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "timestamp", Value: -1}},
		},
		{
			Keys: bson.D{{Key: "action", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "resource_type", Value: 1}},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create audit_logs indexes: %w", err)
	}

	// OTP sessions collection with TTL index
	otpCol := db.database.Collection("otp_sessions")
	_, err = otpCol.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "username", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0), // TTL index
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create otp_sessions indexes: %w", err)
	}

	// API keys collection — unique on the hash (lookup key), indexed by owner,
	// and a TTL index so keys created with an expiration auto-delete once past
	// it (keys with no expires_at are untouched — Mongo's TTL monitor simply
	// skips documents missing the field). AuthMiddleware also checks expiry
	// itself at request time, so correctness never depends on this sweep's lag.
	apiKeysCol := db.database.Collection("api_keys")
	_, err = apiKeysCol.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "key_hash", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "user_id", Value: 1}},
		},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0).SetSparse(true),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create api_keys indexes: %w", err)
	}

	db.logger.Info("MongoDB indexes created successfully")
	return nil
}

func (db *MongoDB) Close(ctx context.Context) error {
	return db.client.Disconnect(ctx)
}

func (db *MongoDB) Database() *mongo.Database {
	return db.database
}

func (db *MongoDB) HealthCheck(ctx context.Context) error {
	return db.client.Ping(ctx, nil)
}

func (db *MongoDB) Ping(ctx context.Context) error {
	return db.client.Ping(ctx, nil)
}
