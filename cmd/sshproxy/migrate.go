package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/iniimport"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/secrets"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/store"
)

// runMigrate imports a legacy config.ini into the database that the proxy now
// treats as the source of truth.
func runMigrate(args []string) {
	if len(args) == 0 {
		printMigrateUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "ini2db":
		runMigrateINI2DB(args[1:])
	case "help", "--help", "-h":
		printMigrateUsage()
	default:
		printError(fmt.Sprintf("unknown migrate subcommand: %s", args[0]))
		printMigrateUsage()
		os.Exit(1)
	}
}

func printMigrateUsage() {
	fmt.Print(`Usage: sshproxy migrate <subcommand> [options]

Subcommands:
  ini2db    import users, routes, policies, and IP rules from config.ini

Run "sshproxy migrate ini2db --help" for the available options.
`)
}

func runMigrateINI2DB(args []string) {
	fs := flag.NewFlagSet("migrate ini2db", flag.ExitOnError)
	configPath := fs.String("config", "/etc/ssh-proxy/config.ini", "path to the config.ini to import")
	driver := fs.String("driver", "sqlite", "database driver: sqlite or postgres")
	dsn := fs.String("dsn", "", "database connection string (required)")
	keySpec := fs.String("encryption-key", "", "32-byte hex key or file:<path>, used to seal imported secrets")
	importKeys := fs.Bool("import-private-keys", false,
		"read the private key files referenced by routes and store them as sealed secrets")
	dryRun := fs.Bool("dry-run", false, "parse and report without writing to the database")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if strings.TrimSpace(*dsn) == "" {
		printError("--dsn is required")
		fs.Usage()
		os.Exit(1)
	}

	if *dryRun {
		// A dry run still needs somewhere to write, so it uses a throwaway
		// in-memory database and reports what a real run would produce.
		*driver = "sqlite"
		*dsn = "file:ini2db-dry-run?mode=memory&cache=shared"
	}

	st, err := store.Open(*driver, *dsn)
	if err != nil {
		printError(fmt.Sprintf("open database: %v", err))
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()

	if spec := strings.TrimSpace(*keySpec); spec != "" {
		provider, err := secrets.LoadStaticProvider(spec)
		if err != nil {
			printError(fmt.Sprintf("load encryption key: %v", err))
			os.Exit(1)
		}
		sealer, err := secrets.NewSealer(provider)
		if err != nil {
			printError(fmt.Sprintf("initialise sealer: %v", err))
			os.Exit(1)
		}
		st.SetSealer(sealer)
	}

	result, err := iniimport.Import(*configPath, st, iniimport.Options{
		ImportPrivateKeys: *importKeys,
	})
	if err != nil {
		printError(fmt.Sprintf("import: %v", err))
		os.Exit(1)
	}

	if *dryRun {
		fmt.Println("Dry run — nothing was written to a persistent database.")
	}
	fmt.Printf("Imported from %s:\n", *configPath)
	fmt.Printf("  users          %d\n", result.Users)
	fmt.Printf("  public keys    %d\n", result.PublicKeys)
	fmt.Printf("  targets        %d\n", result.Targets)
	fmt.Printf("  access rules   %d\n", result.AccessRules)
	fmt.Printf("  credentials    %d\n", result.Credentials)
	fmt.Printf("  sealed secrets %d\n", result.Secrets)
	fmt.Printf("  ip rules       %d\n", result.IPRules)

	if len(result.Warnings) > 0 {
		fmt.Printf("\n%d item(s) need attention:\n", len(result.Warnings))
		for _, w := range result.Warnings {
			fmt.Printf("  - %s\n", w)
		}
	}
}
