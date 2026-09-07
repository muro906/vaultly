// Package config loads and validates runtime configuration from the
// environment.
//
// Validation is strict and happens once, at startup: a server that boots with
// a malformed master key or a missing signing secret would fail later, at the
// worst possible moment, with secrets already in flight. Every problem found
// is reported at once so a misconfigured deployment can be fixed in one pass.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"vaultly/backend/internal/crypto"
)

// Environment names the deployment mode. It gates behaviour that must differ
// between local development and production, such as whether session cookies
// are marked Secure.
type Environment string

const (
	EnvDevelopment Environment = "development"
	EnvProduction  Environment = "production"
	EnvTest        Environment = "test"
)

// IsProduction reports whether the server is running in production mode.
func (e Environment) IsProduction() bool { return e == EnvProduction }

// Config is the fully validated configuration for the API server.
type Config struct {
	DatabaseURL string

	// MasterKey is the base64-encoded key that wraps every data encryption
	// key. It is kept encoded here and decoded exactly once, by Keyring.
	MasterKey string

	JWTSecret       []byte
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration

	Port        int
	Environment Environment
	LogLevel    slog.Level

	CORSAllowedOrigins []string

	// TrustProxy controls whether X-Forwarded-For is honoured when
	// determining a client's IP. It must only be enabled behind a proxy that
	// overwrites the header, since IP allowlisting and rate limiting both
	// depend on that address being truthful.
	TrustProxy bool
}

// Keyring builds the encryption keyring described by this configuration.
func (c *Config) Keyring() (*crypto.Keyring, error) {
	return crypto.NewKeyringFromBase64(c.MasterKey)
}

// Addr returns the listen address for the HTTP server.
func (c *Config) Addr() string { return fmt.Sprintf(":%d", c.Port) }

// Load reads configuration from the process environment and validates it.
// The returned error, if any, describes every problem found.
func Load() (*Config, error) {
	var problems []string
	fail := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	cfg := &Config{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		MasterKey:   os.Getenv("VAULTLY_MASTER_KEY"),
	}

	// --- Database ---------------------------------------------------------
	if cfg.DatabaseURL == "" {
		fail("DATABASE_URL is required")
	} else if u, err := url.Parse(cfg.DatabaseURL); err != nil {
		fail("DATABASE_URL is not a valid URL: %v", err)
	} else if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		fail("DATABASE_URL must use the postgres:// scheme, got %q", u.Scheme)
	}

	// --- Master key -------------------------------------------------------
	// Decoded eagerly so a bad key is caught here rather than on first write.
	switch {
	case cfg.MasterKey == "":
		fail("VAULTLY_MASTER_KEY is required (generate one with: openssl rand -base64 32)")
	default:
		if _, err := crypto.NewKeyringFromBase64(cfg.MasterKey); err != nil {
			fail("VAULTLY_MASTER_KEY is invalid: %v "+
				"(it must be exactly 32 bytes, base64-encoded)", err)
		}
	}

	// --- JWT --------------------------------------------------------------
	secret := os.Getenv("JWT_SECRET")
	const minJWTSecretLen = 32
	switch {
	case secret == "":
		fail("JWT_SECRET is required (generate one with: openssl rand -base64 48)")
	case len(secret) < minJWTSecretLen:
		fail("JWT_SECRET must be at least %d characters, got %d", minJWTSecretLen, len(secret))
	default:
		cfg.JWTSecret = []byte(secret)
	}

	var err error
	if cfg.AccessTokenTTL, err = durationEnv("ACCESS_TOKEN_TTL", 15*time.Minute); err != nil {
		fail("%v", err)
	}
	if cfg.RefreshTokenTTL, err = durationEnv("REFRESH_TOKEN_TTL", 30*24*time.Hour); err != nil {
		fail("%v", err)
	}
	if cfg.AccessTokenTTL > 0 && cfg.RefreshTokenTTL > 0 && cfg.AccessTokenTTL >= cfg.RefreshTokenTTL {
		fail("ACCESS_TOKEN_TTL (%s) must be shorter than REFRESH_TOKEN_TTL (%s)",
			cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	}

	// --- Server -----------------------------------------------------------
	if cfg.Port, err = portEnv("PORT", 8080); err != nil {
		fail("%v", err)
	}

	cfg.Environment = Environment(stringEnv("ENVIRONMENT", string(EnvDevelopment)))
	switch cfg.Environment {
	case EnvDevelopment, EnvProduction, EnvTest:
	default:
		fail("ENVIRONMENT must be one of development, production, test; got %q", cfg.Environment)
	}

	if cfg.LogLevel, err = logLevelEnv("LOG_LEVEL", slog.LevelInfo); err != nil {
		fail("%v", err)
	}

	cfg.CORSAllowedOrigins = splitAndTrim(stringEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000"))
	for _, origin := range cfg.CORSAllowedOrigins {
		if origin == "*" {
			// A wildcard cannot be combined with credentialed requests, and
			// this API authenticates with cookies.
			fail("CORS_ALLOWED_ORIGINS may not contain \"*\"; list explicit origins")
			continue
		}
		u, parseErr := url.Parse(origin)
		if parseErr != nil || u.Scheme == "" || u.Host == "" {
			fail("CORS_ALLOWED_ORIGINS entry %q is not a valid origin (want scheme://host[:port])", origin)
		}
	}

	if cfg.TrustProxy, err = boolEnv("TRUST_PROXY", false); err != nil {
		fail("%v", err)
	}

	if len(problems) > 0 {
		return nil, fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return cfg, nil
}

func stringEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s is not a valid duration (e.g. 15m, 24h): %q", key, raw)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %s", key, d)
	}
	return d, nil
}

func portEnv(key string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%s must be a port between 1 and 65535, got %q", key, raw)
	}
	return port, nil
}

func boolEnv(key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean (true/false), got %q", key, raw)
	}
	return v, nil
}

func logLevelEnv(key string, fallback slog.Level) (slog.Level, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(raw)); err != nil {
		return 0, fmt.Errorf("%s must be one of debug, info, warn, error; got %q", key, raw)
	}
	return level, nil
}

func splitAndTrim(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ErrNoConfig is returned by helpers that expect configuration to be present.
var ErrNoConfig = errors.New("config: not loaded")
