package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/lmittmann/tint"
	"github.com/peterbourgon/ff/v3"
	"github.com/streamplace/oatproxy/pkg/oatproxy"
)

func main() {
	err := Run()
	if err != nil {
		slog.Error("exited uncleanly", "error", err)
		os.Exit(1)
	}
}

const UPSTREAM_KEY = "upstream"
const DOWNSTREAM_KEY = "downstream"

func Run() error {
	flag.Set("logtostderr", "true")
	fs := flag.NewFlagSet("oatproxy", flag.ExitOnError)
	noColor := fs.Bool("no-color", false, "disable colorized logging")
	host := fs.String("host", "", "public HTTPS address where this OAuth provider is hosted (ex example.com, no https:// prefix)")
	dbPath := fs.String("db", "oatproxy.sqlite3", "path to the database file or postgres connection string")
	verbose := fs.Bool("v", false, "enable verbose logging")
	scope := fs.String("scope", "", "scope to use for the OAuth provider (defaults to the scope field in client metadata, or 'atproto transition:generic')")
	clientMetadata := fs.String("client-metadata", "", "JSON client metadata, path to a JSON file, or https:// URL serving client metadata")
	clientMetadataRefresh := fs.Duration("client-metadata-refresh", 5*time.Minute, "interval to re-fetch URL-sourced client metadata (set 0 to disable)")
	httpAddr := fs.String("http-addr", ":8080", "HTTP address to listen on")
	upstreamHost := fs.String("upstream-host", "", "act as a reverse proxy for this upstream host (ex http://localhost:8081)")
	defaultPDS := fs.String("default-pds", "", "default PDS to use if no handle is provided")
	downstreamClientMetadataPath := fs.String("downstream-client-metadata-path", "", "URL path where the downstream client metadata is served (defaults to /oauth/downstream/client-metadata.json)")
	upstreamClientMetadataPath := fs.String("upstream-client-metadata-path", "", "URL path where the upstream client metadata is served (defaults to /oauth/upstream/client-metadata.json)")
	// version := fs.Bool("version", false, "print version and exit")

	err := ff.Parse(
		fs, os.Args[1:],
		ff.WithEnvVarPrefix("OATPROXY"),
	)
	if err != nil {
		return err
	}
	err = flag.CommandLine.Parse(nil)
	if err != nil {
		return err
	}

	if *host == "" {
		return fmt.Errorf("host is required")
	}

	opts := &tint.Options{
		Level:      slog.LevelInfo,
		TimeFormat: time.RFC3339,
		NoColor:    *noColor,
	}
	if *verbose {
		opts.Level = slog.LevelDebug
	}
	logger := slog.New(
		tint.NewHandler(os.Stderr, opts),
	)

	slog.SetDefault(logger)

	store, err := NewStore(*dbPath, logger, *verbose)
	if err != nil {
		return err
	}

	if *clientMetadata == "" {
		return fmt.Errorf("client-metadata is required")
	}
	isURL := strings.HasPrefix(*clientMetadata, "https://") || strings.HasPrefix(*clientMetadata, "http://")
	meta, err := loadClientMetadata(*clientMetadata)
	if err != nil {
		return err
	}
	resolveScope := func(m *oatproxy.OAuthClientMetadata) string {
		if *scope != "" {
			return *scope
		}
		if m.Scope != "" {
			return m.Scope
		}
		return "atproto transition:generic"
	}
	resolvedScope := resolveScope(meta)

	upstreamKey, err := store.GetKey(UPSTREAM_KEY)
	if err != nil {
		return err
	}
	downstreamKey, err := store.GetKey(DOWNSTREAM_KEY)
	if err != nil {
		return err
	}
	o := oatproxy.New(&oatproxy.Config{
		Host:               *host,
		CreateOAuthSession: store.CreateOAuthSession,
		UpdateOAuthSession: store.UpdateOAuthSession,
		GetOAuthSession:    store.GetOAuthSession,
		Scope:              resolvedScope,
		ClientMetadata:     meta,
		UpstreamJWK:        upstreamKey,
		DownstreamJWK:      downstreamKey,
		DefaultPDS:         *defaultPDS,
		DownstreamClientMetadataPath: *downstreamClientMetadataPath,
		UpstreamClientMetadataPath:   *upstreamClientMetadataPath,
	})

	if *upstreamHost != "" {
		reverse := &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				u, err := url.Parse(*upstreamHost)
				if err != nil {
					logger.Error("failed to parse proxy host", "error", err)
					return
				}
				u.RawPath = r.In.URL.RawPath
				u.RawQuery = r.In.URL.RawQuery
				logger.Info("proxying request", "url", u)
				r.SetURL(u)
			},
		}

		reverseEcho := func(c echo.Context) error {
			reverse.ServeHTTP(c.Response().Writer, c.Request())
			c.Response().Committed = true
			return nil
		}

		o.Echo.Any("/*", reverseEcho)
	}

	if isURL && *clientMetadataRefresh > 0 {
		go func() {
			ticker := time.NewTicker(*clientMetadataRefresh)
			defer ticker.Stop()
			for range ticker.C {
				next, err := loadClientMetadata(*clientMetadata)
				if err != nil {
					logger.Warn("failed to refresh client metadata, keeping previous", "error", err, "source", *clientMetadata)
					continue
				}
				o.SetClientMetadata(next, resolveScope(next))
				logger.Info("refreshed client metadata", "source", *clientMetadata)
			}
		}()
	}

	server := &http.Server{
		Addr:    *httpAddr,
		Handler: o.Echo,
	}

	logger.Info("starting server", "addr", *httpAddr)
	if err := server.ListenAndServe(); err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

func loadClientMetadata(source string) (*oatproxy.OAuthClientMetadata, error) {
	if source == "" {
		return nil, fmt.Errorf("client-metadata is required")
	}
	var bs []byte
	switch {
	case source[0] == '{':
		bs = []byte(source)
	case strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "http://"):
		resp, err := http.Get(source)
		if err != nil {
			return nil, fmt.Errorf("fetching client-metadata from %s: %w", source, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetching client-metadata from %s: status %d", source, resp.StatusCode)
		}
		bs, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("reading client-metadata from %s: %w", source, err)
		}
	default:
		var err error
		bs, err = os.ReadFile(source)
		if err != nil {
			return nil, err
		}
	}
	meta := &oatproxy.OAuthClientMetadata{}
	if err := json.Unmarshal(bs, meta); err != nil {
		return nil, fmt.Errorf("parsing client-metadata: %w", err)
	}
	return meta, nil
}
