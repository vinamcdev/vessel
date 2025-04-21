package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
)

type UserRegistration struct {
	UID string `json:"uid" binding:"required,max=64"`
}

type Message struct {
	Recipient string `json:"recipient" binding:"required,max=64"`
	Data      string `json:"data" binding:"required,max=1048576"`
}

type KeyPair struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

var rdb *redis.Client
var ctx = context.Background()

func main() {
	rdb = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_ADDR"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})

	router := gin.Default()

	router.POST("/register", registerUser)
	router.GET("/key/:uid", getPublicKey)
	router.POST("/send", sendMessage)
	router.GET("/messages/:uid", getMessages)

	router.GET("/health", func(c *gin.Context) {
		if err := rdb.Ping(ctx).Err(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "redis unavailable"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	router.Run(":56565")
}

func registerUser(c *gin.Context) {
	var reg UserRegistration
	if err := c.ShouldBindJSON(&reg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Key generation failed"})
		return
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	})

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	ctx := c.Request.Context()
	result, err := rdb.HSetNX(ctx, "users", reg.UID, string(publicKeyPEM)).Result()

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed"})
		return
	}
	if !result {
		c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		return
	}

	c.JSON(http.StatusCreated, KeyPair{
		PublicKey:  string(publicKeyPEM),
		PrivateKey: string(privateKeyPEM),
	})
}

func getPublicKey(c *gin.Context) {
	uid := c.Param("uid")
	publicKey, err := rdb.HGet(c.Request.Context(), "users", uid).Result()

	if errors.Is(err, redis.Nil) {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"public_key": publicKey})
}

func sendMessage(c *gin.Context) {
	var msg Message
	if err := c.ShouldBindJSON(&msg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid message format"})
		return
	}

	exists, err := rdb.HExists(ctx, "users", msg.Recipient).Result()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Recipient verification failed"})
		return
	}
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Recipient not found"})
		return
	}

	key := "messages:" + msg.Recipient
	err = rdb.LPush(ctx, key, msg.Data).Err()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Message delivery failed"})
		return
	}

	rdb.Expire(ctx, key, 168*time.Hour)

	c.Status(http.StatusCreated)
}

func getMessages(c *gin.Context) {
	uid := c.Param("uid")

	messages, err := rdb.LRange(c.Request.Context(), "messages:"+uid, 0, -1).Result()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve messages"})
		return
	}

	rdb.Del(c.Request.Context(), "messages:"+uid)

	c.JSON(http.StatusOK, gin.H{"messages": messages})
}
