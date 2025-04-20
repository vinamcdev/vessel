package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
)

type UserRegistration struct {
	UID string `json:"uid" binding:"required,max=64"`
}

type KeyPair struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

var rdb *redis.Client

func main() {
	rdb = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_ADDR"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})

	router := gin.Default()

	router.POST("/register", registerUser)
	router.GET("/key/:uid", getPublicKey)

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
