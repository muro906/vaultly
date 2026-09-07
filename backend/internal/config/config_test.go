package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"vaultly/backend/internal/crypto"
)

// validEnv is the smallest environment that loads successfully.
func validEnv(t *testing.T) map[string]string {
	t.Helper()
	key, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	return map[string]string{
		"DATABASE_URL":       "postgres://user:pass@localhost:5432/vaultly?sslmode=disable",
		"VAULTLY_MASTER_KEY": key,
		"JWT_SECRET":         strings.Repeat("s", 48),
	}
}

// setEnv applies env to the process for the duration of the test.
func setEnv(t *testing.T, env map[string]string) {
	t.Helper()
	// Clear everything Load reads so tests never inherit the developer's shell.
	for _, key := range []string{
		"DATABASE_URL", "VAULTLY_MASTER_KEY", "JWT_SECRET",
		"ACCESS_TOKEN_TTL", "REFRESH_TOKEN_TTL", "PORT", "ENVIRONMENT",
		"LOG_LEVEL", "CORS_ALLOWED_ORIGINS", "TRUST_PROXY",
	} {
		t.Setenv(key, "")
	}
	for key, value := range env {
		t.Setenv(key, value)
	}
}

func TestLoadDefaults(t *testing.T) {
	setEnv(t, validEnv(t))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080", cfg.Port)
	}
	if cfg.Environment != EnvDevelopment {
		t.Errorf("Environment = %q, want development", cfg.Environment)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want info", cfg.LogLevel)
	}
	if cfg.AccessTokenTTL != 15*time.Minute {
		t.Errorf("AccessTokenTTL = %s, want 15m", cfg.AccessTokenTTL)
	}
	if cfg.TrustProxy {
		t.Error("TrustProxy defaulted to true; it must default to false")
	}
	if got, want := cfg.Addr(), ":8080"; got != want {
		t.Errorf("Addr() = %q, want %q", got, want)
	}

	// The loaded key must actually build a keyring.
	if _, err := cfg.Keyring(); err != nil {
		t.Errorf("Keyring: %v", err)
	}
}

func TestLoadRejectsMissingRequiredValues(t *testing.T) {
	setEnv(t, map[string]string{})

	_, err := Load()
	if err == nil {
		t.Fatal("expected an error when nothing is configured")
	}
	// All problems are reported together so a broken deployment can be fixed
	// in one pass rather than one restart per missing variable.
	for _, want := range []string{"DATABASE_URL", "VAULTLY_MASTER_KEY", "JWT_SECRET"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	cases := map[string]struct {
		override map[string]string
		want     string
	}{
		"master key not base64": {
			map[string]string{"VAULTLY_MASTER_KEY": "!!!not base64!!!"},
			"VAULTLY_MASTER_KEY is invalid",
		},
		"master key wrong length": {
			map[string]string{"VAULTLY_MASTER_KEY": "c2hvcnQ="},
			"32 bytes",
		},
		"jwt secret too short": {
			map[string]string{"JWT_SECRET": "tooshort"},
			"JWT_SECRET must be at least",
		},
		"database url wrong scheme": {
			map[string]string{"DATABASE_URL": "mysql://localhost/vaultly"},
			"postgres:// scheme",
		},
		"port out of range": {
			map[string]string{"PORT": "70000"},
			"PORT must be a port",
		},
		"port not a number": {
			map[string]string{"PORT": "eighty"},
			"PORT must be a port",
		},
		"unknown environment": {
			map[string]string{"ENVIRONMENT": "staging"},
			"ENVIRONMENT must be one of",
		},
		"bad log level": {
			map[string]string{"LOG_LEVEL": "verbose"},
			"LOG_LEVEL must be one of",
		},
		"bad duration": {
			map[string]string{"ACCESS_TOKEN_TTL": "15 minutes"},
			"not a valid duration",
		},
		"negative duration": {
			map[string]string{"ACCESS_TOKEN_TTL": "-5m"},
			"must be positive",
		},
		"access ttl exceeds refresh ttl": {
			map[string]string{"ACCESS_TOKEN_TTL": "48h", "REFRESH_TOKEN_TTL": "1h"},
			"must be shorter than",
		},
		"wildcard cors origin": {
			// A wildcard cannot be combined with cookie credentials, so it
			// must be rejected rather than silently failing at runtime.
			map[string]string{"CORS_ALLOWED_ORIGINS": "*"},
			"may not contain",
		},
		"malformed cors origin": {
			map[string]string{"CORS_ALLOWED_ORIGINS": "localhost:3000"},
			"not a valid origin",
		},
		"bad boolean": {
			map[string]string{"TRUST_PROXY": "yes please"},
			"must be a boolean",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			env := validEnv(t)
			for k, v := range tc.override {
				env[k] = v
			}
			setEnv(t, env)

			_, err := Load()
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestLoadParsesOverrides(t *testing.T) {
	env := validEnv(t)
	env["PORT"] = "9090"
	env["ENVIRONMENT"] = "production"
	env["LOG_LEVEL"] = "debug"
	env["ACCESS_TOKEN_TTL"] = "5m"
	env["REFRESH_TOKEN_TTL"] = "168h"
	env["TRUST_PROXY"] = "true"
	env["CORS_ALLOWED_ORIGINS"] = "https://app.example.com, https://admin.example.com"
	setEnv(t, env)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if cfg.Port != 9090 {
		t.Errorf("Port = %d, want 9090", cfg.Port)
	}
	if !cfg.Environment.IsProduction() {
		t.Error("IsProduction() = false, want true")
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %v, want debug", cfg.LogLevel)
	}
	if cfg.AccessTokenTTL != 5*time.Minute {
		t.Errorf("AccessTokenTTL = %s, want 5m", cfg.AccessTokenTTL)
	}
	if !cfg.TrustProxy {
		t.Error("TrustProxy = false, want true")
	}
	// Whitespace around the comma must be trimmed, since env files often have it.
	want := []string{"https://app.example.com", "https://admin.example.com"}
	if len(cfg.CORSAllowedOrigins) != len(want) {
		t.Fatalf("CORSAllowedOrigins = %v, want %v", cfg.CORSAllowedOrigins, want)
	}
	for i, origin := range want {
		if cfg.CORSAllowedOrigins[i] != origin {
			t.Errorf("origin %d = %q, want %q", i, cfg.CORSAllowedOrigins[i], origin)
		}
	}
}

func TestEnvironmentIsProduction(t *testing.T) {
	if !EnvProduction.IsProduction() {
		t.Error("production must report IsProduction")
	}
	for _, env := range []Environment{EnvDevelopment, EnvTest, "other"} {
		if env.IsProduction() {
			t.Errorf("%q must not report IsProduction", env)
		}
	}
}
