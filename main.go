package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/sessions"

	"github.com/gordyf/traefik-forward-auth/authentication"

	"github.com/gordyf/traefik-forward-auth/api/storage/v1alpha1"
	"github.com/gordyf/traefik-forward-auth/configuration"
	"github.com/gordyf/traefik-forward-auth/handlers"
	logger "github.com/gordyf/traefik-forward-auth/log"
	"github.com/gordyf/traefik-forward-auth/storage"
)

// Main
func main() {
	// Parse options
	config, err := configuration.NewConfig(os.Args[1:])
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}

	// Setup logger
	log := logger.NewDefaultLogger(config.LogLevel, config.LogFormat)

	// Perform config validation
	config.Validate()

	// Query the OIDC provider
	if err := config.LoadOIDCProviderConfiguration(); err != nil {
		log.Fatalln(err.Error())
	}

	authenticator := authentication.NewAuthenticator(config)

	var userInfoStore v1alpha1.UserInfoInterface
	// Prepare cookie session store (first key is for auth, the second one for encryption)
	hashKey := []byte(config.SecretString)
	blockKey := []byte(config.EncryptionKeyString)
	cookieStore := sessions.NewCookieStore(hashKey, blockKey)
	cookieStore.Options.MaxAge = int(config.Lifetime / time.Second)
	cookieStore.Options.HttpOnly = true
	cookieStore.Options.Secure = true

	userInfoStore = &storage.GorillaUserInfoStore{
		SessionStore: cookieStore,
		SessionName:  config.ClaimsSessionName,
		Auth:         authenticator,
	}

	// Build server
	server := handlers.NewServer(userInfoStore, config)

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)
	http.HandleFunc(config.CallbackPath, server.AuthCallbackHandler)

	// Start
	log.Debugf("starting with options: %s", config)
	log.Info("listening on :4181")
	log.Info(http.ListenAndServe(":4181", nil))
}
