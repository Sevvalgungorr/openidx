package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/authstore"
	"github.com/openidx/openidx/agent/internal/control"
	"github.com/openidx/openidx/agent/internal/enrollment"
	"github.com/openidx/openidx/agent/internal/remotesupport"
	"github.com/openidx/openidx/agent/internal/sso"
	"github.com/openidx/openidx/agent/internal/tray"
	"github.com/openidx/openidx/agent/internal/updater"
	"github.com/openidx/openidx/agent/internal/winservice"
)

// resolveServer returns the --server flag if set, else the enrolled server URL.
func resolveServer(cmd *cobra.Command) string {
	if s, _ := cmd.Flags().GetString("server"); s != "" {
		return s
	}
	if cfg, err := agent.LoadConfig(configDir); err == nil {
		return cfg.ServerURL
	}
	return ""
}

// defaultConfigDir returns the platform-appropriate config/credential directory:
// %ProgramData%\OpenIDX\agent on Windows, /etc/openidx-agent elsewhere.
func defaultConfigDir() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "OpenIDX", "agent")
	}
	return "/etc/openidx-agent"
}

// Version information injected via ldflags at build time.
var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "none"
)

var (
	configDir string
	verbose   bool
	logger    *zap.Logger
)

func main() {
	// Deep-link entry: the OS invokes `openidx-agent openidx://enroll?code=..&server=..`
	// (from a scanned QR / clicked link). Rewrite it into the enroll command.
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "openidx://") {
		if args, ok := deepLinkToArgs(os.Args[1]); ok {
			os.Args = append([]string{os.Args[0]}, args...)
		}
	}
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// deepLinkToArgs converts an openidx://enroll?code=..&server=.. deep-link into
// enroll command args. Returns false if it isn't a valid enroll link.
func deepLinkToArgs(raw string) ([]string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host != "enroll" {
		return nil, false
	}
	code := u.Query().Get("code")
	if code == "" {
		return nil, false
	}
	args := []string{"enroll", "--code", code}
	if s := u.Query().Get("server"); s != "" {
		args = append(args, "--server", s)
	}
	return args, true
}

var rootCmd = &cobra.Command{
	Use:   "openidx-agent",
	Short: "OpenIDX endpoint agent",
	Long: `openidx-agent is the endpoint agent for the OpenIDX Zero Trust Access Platform.
It enrolls devices, enforces access policies, and reports health status back to the platform.`,
	Version: fmt.Sprintf("%s (commit: %s, built: %s)", Version, Commit, BuildTime),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		if verbose {
			logger, err = zap.NewDevelopment()
		} else {
			logger, err = zap.NewProduction()
		}
		if err != nil {
			return fmt.Errorf("initializing logger: %w", err)
		}
		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if logger != nil {
			_ = logger.Sync()
		}
	},
}

var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll this endpoint with an OpenIDX server",
	Long: `Enroll this endpoint with an OpenIDX server using a one-time enrollment token.
The agent will contact the specified server, validate the token, and store the
resulting credentials in the config directory for subsequent runs.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		token, _ := cmd.Flags().GetString("token")
		code, _ := cmd.Flags().GetString("code")
		if token == "" {
			token = code // the enrollment-session code is the bearer token
		}
		if token == "" {
			return fmt.Errorf("either --token or --code is required")
		}
		server, _ := cmd.Flags().GetString("server")
		manifestURL, _ := cmd.Flags().GetString("manifest-url")

		logger.Info("enrolling agent",
			zap.String("server", server),
			zap.String("config_dir", configDir),
		)

		result, err := enrollment.EnrollWithManifest(logger, server, token, configDir, manifestURL)
		if err != nil {
			return fmt.Errorf("enrollment failed: %w", err)
		}

		cfg := result.AgentConfig

		fmt.Printf("Enrollment successful!\n")
		fmt.Printf("  Server:    %s\n", cfg.ServerURL)
		fmt.Printf("  Agent ID:  %s\n", cfg.AgentID)
		fmt.Printf("  Device ID: %s\n", cfg.DeviceID)
		fmt.Printf("  Config:    %s\n", configDir)
		if result.ZitiIdentity != "" {
			fmt.Printf("  Ziti:      %s\n", result.ZitiIdentity)
		}

		return nil
	},
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the endpoint agent",
	Long: `Start the OpenIDX endpoint agent. The agent will load its enrollment credentials
from the config directory, establish a secure connection to the OpenIDX server, and
begin enforcing access policies and reporting health checks.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logger.Info("starting agent",
			zap.String("config_dir", configDir),
		)

		a, err := agent.NewAgent(logger, configDir)
		if err != nil {
			return fmt.Errorf("creating agent: %w", err)
		}

		a.RegisterBuiltinChecks()
		a.LoadPlugins()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			sig := <-sigCh
			logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
			cancel()
		}()

		if err := a.Run(ctx); err != nil && err != context.Canceled {
			return fmt.Errorf("agent run failed: %w", err)
		}

		return nil
	},
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the headless control engine (local API for a desktop GUI)",
	Long: `Start the OpenIDX native-client engine and expose its local control API.

A desktop GUI connects to the control server to drive sign-in, enrollment,
posture, PAM, and Ziti dial from the same engine the CLI uses. The listener is a
0600 Unix domain socket on macOS/Linux, or a loopback TCP port guarded by a
bearer token on Windows. The engine blocks until interrupted.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logger.Info("starting control engine", zap.String("config_dir", configDir))

		engine, err := control.NewEngine(configDir, logger)
		if err != nil {
			return fmt.Errorf("creating engine: %w", err)
		}
		srv, err := control.NewServer(engine, logger)
		if err != nil {
			return fmt.Errorf("creating control server: %w", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			sig := <-sigCh
			logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
			cancel()
		}()

		logger.Info("control API ready", zap.String("addr", srv.Addr()))
		fmt.Printf("OpenIDX control engine listening at %s\n", srv.Addr())

		if err := srv.Serve(ctx); err != nil {
			return fmt.Errorf("control server failed: %w", err)
		}
		return nil
	},
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Sign in to OpenIDX (browser PKCE flow) and cache the session",
	RunE: func(cmd *cobra.Command, args []string) error {
		server := resolveServer(cmd)
		if server == "" {
			return fmt.Errorf("no server: pass --server or enroll first")
		}
		t, err := sso.Login(cmd.Context(), server)
		if err != nil {
			return fmt.Errorf("sign-in failed: %w", err)
		}
		if err := authstore.Save(configDir, t); err != nil {
			return fmt.Errorf("saving session: %w", err)
		}
		fmt.Println("Signed in.")
		return nil
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Sign out and clear the cached session",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := authstore.Clear(configDir); err != nil {
			return err
		}
		fmt.Println("Signed out.")
		return nil
	},
}

var trayCmd = &cobra.Command{
	Use:   "tray",
	Short: "Run the OpenIDX system-tray app (Windows)",
	RunE: func(cmd *cobra.Command, args []string) error {
		server := resolveServer(cmd)
		if server == "" {
			return fmt.Errorf("no server: pass --server or enroll first")
		}
		return tray.Run(logger, configDir, server)
	},
}

// serviceCmd groups Windows-service lifecycle subcommands.
var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage the OpenIDX agent Windows service",
	Long:  "Install, uninstall, or run the OpenIDX agent as a Windows service (Windows only).",
}

var serviceRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run under the Windows Service control manager (invoked by the SCM)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return winservice.Run(logger, configDir, Version)
	},
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Check for and (with --apply) install a newer OpenIDX client",
	RunE: func(cmd *cobra.Command, args []string) error {
		url, _ := cmd.Flags().GetString("manifest-url")
		if url == "" {
			if cfg, err := agent.LoadConfig(configDir); err == nil {
				url = cfg.UpdateManifestURL
			}
		}
		if url == "" {
			return fmt.Errorf("no update manifest URL: pass --manifest-url or set update_manifest_url in config")
		}
		m, err := updater.Fetch(cmd.Context(), url)
		if err != nil {
			return err
		}
		if !updater.Newer(Version, m.Version) {
			fmt.Printf("Up to date (current %s, latest %s).\n", Version, m.Version)
			return nil
		}
		fmt.Printf("Update available: %s -> %s\n", Version, m.Version)
		if apply, _ := cmd.Flags().GetBool("apply"); !apply {
			fmt.Println("Run with --apply to install.")
			return nil
		}
		applied, newV, err := updater.CheckAndApply(cmd.Context(), url, Version)
		if err != nil {
			return fmt.Errorf("update failed: %w", err)
		}
		if applied {
			fmt.Printf("Installing %s (msiexec launched)...\n", newV)
		}
		return nil
	},
}

// capabilitiesCmd reports, as JSON, what this build can do at runtime — most
// importantly whether it can capture the screen for remote support. This makes
// the "video-less agent" state observable: CI verifies the packaged exe reports
// screen_capture=true, and an operator can check a deployed agent instead of
// guessing why a session shows no screen.
var capabilitiesCmd = &cobra.Command{
	Use:   "capabilities",
	Short: "Print this build's runtime capabilities (JSON), e.g. screen capture",
	RunE: func(cmd *cobra.Command, args []string) error {
		screenCapture := false
		if src, err := remotesupport.NewScreenSource(10); err == nil {
			screenCapture = remotesupport.SourceHasVideo(src)
			src.Close()
		}
		out := map[string]any{
			"version":        Version,
			"commit":         Commit,
			"screen_capture": screenCapture,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	},
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install and start the OpenIDX agent service (LocalSystem, auto-start)",
	RunE: func(cmd *cobra.Command, args []string) error {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("resolving executable path: %w", err)
		}
		if err := winservice.Install(exe, configDir); err != nil {
			return err
		}
		logger.Info("service installed", zap.String("name", winservice.ServiceName))
		return nil
	},
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop and remove the OpenIDX agent service",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := winservice.Uninstall(); err != nil {
			return err
		}
		logger.Info("service uninstalled", zap.String("name", winservice.ServiceName))
		return nil
	},
}

func init() {
	// Persistent flags available to all subcommands.
	rootCmd.PersistentFlags().StringVar(&configDir, "config-dir", defaultConfigDir(),
		"directory for agent configuration and credentials")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"enable verbose (debug) logging")

	// enroll-specific flags.
	enrollCmd.Flags().String("token", "", "one-time enrollment token")
	enrollCmd.Flags().String("code", "", "enrollment session code from the Add-a-device wizard / deep-link")
	enrollCmd.Flags().String("server", "https://openidx.example.com", "OpenIDX server URL")
	enrollCmd.Flags().String("manifest-url", "", "update manifest URL to persist for self-update (optional)")
	// Either --token or --code is required; validated in RunE.

	serviceCmd.AddCommand(serviceRunCmd)
	serviceCmd.AddCommand(serviceInstallCmd)
	serviceCmd.AddCommand(serviceUninstallCmd)

	loginCmd.Flags().String("server", "", "OpenIDX server URL (defaults to the enrolled server)")
	trayCmd.Flags().String("server", "", "OpenIDX server URL (defaults to the enrolled server)")
	updateCmd.Flags().String("manifest-url", "", "version manifest URL (defaults to config update_manifest_url)")
	updateCmd.Flags().Bool("apply", false, "download and install the update if one is available")

	rootCmd.AddCommand(enrollCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(serviceCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(trayCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(capabilitiesCmd)
}
