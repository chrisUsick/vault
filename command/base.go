package command

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/token"
	"github.com/kr/text"
	"github.com/mitchellh/cli"
	"github.com/pkg/errors"
	"github.com/posener/complete"
)

// maxLineLength is the maximum width of any line.
const maxLineLength int = 78

// reRemoveWhitespace is a regular expression for stripping whitespace from
// a string.
var reRemoveWhitespace = regexp.MustCompile(`[\s]+`)

type TokenHelperFunc func() (token.TokenHelper, error)

type BaseCommand struct {
	UI cli.Ui

	flags     *FlagSets
	flagsOnce sync.Once

	flagAddress       string
	flagCACert        string
	flagCAPath        string
	flagClientCert    string
	flagClientKey     string
	flagTLSServerName string
	flagTLSSkipVerify bool
	flagWrapTTL       time.Duration

	flagFormat string
	flagField  string

	tokenHelper TokenHelperFunc

	// For testing
	client *api.Client
}

// Client returns the HTTP API client. The client is cached on the command to
// save performance on future calls.
func (c *BaseCommand) Client() (*api.Client, error) {
	// Read the test client if present
	if c.client != nil {
		return c.client, nil
	}

	config := api.DefaultConfig()

	if err := config.ReadEnvironment(); err != nil {
		return nil, errors.Wrap(err, "failed to read environment")
	}

	if c.flagAddress != "" {
		config.Address = c.flagAddress
	}

	// If we need custom TLS configuration, then set it
	if c.flagCACert != "" || c.flagCAPath != "" || c.flagClientCert != "" ||
		c.flagClientKey != "" || c.flagTLSServerName != "" || c.flagTLSSkipVerify {
		t := &api.TLSConfig{
			CACert:        c.flagCACert,
			CAPath:        c.flagCAPath,
			ClientCert:    c.flagClientCert,
			ClientKey:     c.flagClientKey,
			TLSServerName: c.flagTLSServerName,
			Insecure:      c.flagTLSSkipVerify,
		}
		config.ConfigureTLS(t)
	}

	// Build the client
	client, err := api.NewClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create client")
	}

	// Set the wrapping function
	client.SetWrappingLookupFunc(c.DefaultWrappingLookupFunc)

	// Get the token if it came in from the environment
	token := client.Token()

	// If we don't have a token, check the token helper
	if token == "" {
		if c.tokenHelper != nil {
			// If we have a token, then set that
			tokenHelper, err := c.tokenHelper()
			if err != nil {
				return nil, errors.Wrap(err, "failed to get token helper")
			}
			token, err = tokenHelper.Get()
			if err != nil {
				return nil, errors.Wrap(err, "failed to retrieve from token helper")
			}
		}
	}

	// Set the token
	if token != "" {
		client.SetToken(token)
	}

	return client, nil
}

// DefaultWrappingLookupFunc is the default wrapping function based on the
// CLI flag.
func (c *BaseCommand) DefaultWrappingLookupFunc(operation, path string) string {
	if c.flagWrapTTL != 0 {
		return c.flagWrapTTL.String()
	}

	return api.DefaultWrappingLookupFunc(operation, path)
}

type FlagSetBit uint

const (
	FlagSetNone FlagSetBit = 1 << iota
	FlagSetHTTP
	FlagSetOutputField
	FlagSetOutputFormat
)

// flagSet creates the flags for this command. The result is cached on the
// command to save performance on future calls.
func (c *BaseCommand) flagSet(bit FlagSetBit) *FlagSets {
	c.flagsOnce.Do(func() {
		set := NewFlagSets(c.UI)

		if bit&FlagSetHTTP != 0 {
			f := set.NewFlagSet("HTTP Options")

			f.StringVar(&StringVar{
				Name:       "address",
				Target:     &c.flagAddress,
				Default:    "https://127.0.0.1:8200",
				EnvVar:     "VAULT_ADDR",
				Completion: complete.PredictAnything,
				Usage:      "Address of the Vault server.",
			})

			f.StringVar(&StringVar{
				Name:       "ca-cert",
				Target:     &c.flagCACert,
				Default:    "",
				EnvVar:     "VAULT_CACERT",
				Completion: complete.PredictFiles("*"),
				Usage: "Path on the local disk to a single PEM-encoded CA " +
					"certificate to verify the Vault server's SSL certificate. This " +
					"takes precendence over -ca-path.",
			})

			f.StringVar(&StringVar{
				Name:       "ca-path",
				Target:     &c.flagCAPath,
				Default:    "",
				EnvVar:     "VAULT_CAPATH",
				Completion: complete.PredictDirs("*"),
				Usage: "Path on the local disk to a directory of PEM-encoded CA " +
					"certificates to verify the Vault server's SSL certificate.",
			})

			f.StringVar(&StringVar{
				Name:       "client-cert",
				Target:     &c.flagClientCert,
				Default:    "",
				EnvVar:     "VAULT_CLIENT_CERT",
				Completion: complete.PredictFiles("*"),
				Usage: "Path on the local disk to a single PEM-encoded CA " +
					"certificate to use for TLS authentication to the Vault server. If " +
					"this flag is specified, -client-key is also required.",
			})

			f.StringVar(&StringVar{
				Name:       "client-key",
				Target:     &c.flagClientKey,
				Default:    "",
				EnvVar:     "VAULT_CLIENT_KEY",
				Completion: complete.PredictFiles("*"),
				Usage: "Path on the local disk to a single PEM-encoded private key " +
					"matching the client certificate from -client-cert.",
			})

			f.StringVar(&StringVar{
				Name:       "tls-server-name",
				Target:     &c.flagTLSServerName,
				Default:    "",
				EnvVar:     "VAULT_TLS_SERVER_NAME",
				Completion: complete.PredictAnything,
				Usage: "Name to use as the SNI host when connecting to the Vault " +
					"server via TLS.",
			})

			f.BoolVar(&BoolVar{
				Name:       "tls-skip-verify",
				Target:     &c.flagTLSSkipVerify,
				Default:    false,
				EnvVar:     "VAULT_SKIP_VERIFY",
				Completion: complete.PredictNothing,
				Usage: "Disable verification of TLS certificates. Using this option " +
					"is highly discouraged and decreases the security of data " +
					"transmissions to and from the Vault server.",
			})

			f.DurationVar(&DurationVar{
				Name:       "wrap-ttl",
				Target:     &c.flagWrapTTL,
				Default:    0,
				EnvVar:     "VAULT_WRAP_TTL",
				Completion: complete.PredictAnything,
				Usage: "Wraps the response in a cubbyhole token with the requested " +
					"TTL. The response is available via the \"vault unwrap\" command. " +
					"The TTL is specified as a numeric string with suffix like \"30s\" " +
					"or \"5m\"",
			})
		}

		if bit&(FlagSetOutputField|FlagSetOutputFormat) != 0 {
			f := set.NewFlagSet("Output Options")

			if bit&FlagSetOutputField != 0 {
				f.StringVar(&StringVar{
					Name:       "field",
					Target:     &c.flagField,
					Default:    "",
					EnvVar:     "",
					Completion: complete.PredictAnything,
					Usage: "Print only the field with the given name. Specifying " +
						"this option will take precedence over other formatting " +
						"directives. The result will not have a trailing newline " +
						"making it idea for piping to other processes.",
				})
			}

			if bit&FlagSetOutputFormat != 0 {
				f.StringVar(&StringVar{
					Name:       "format",
					Target:     &c.flagFormat,
					Default:    "table",
					EnvVar:     "VAULT_FORMAT",
					Completion: complete.PredictSet("table", "json", "yaml"),
					Usage: "Print the output in the given format. Valid formats " +
						"are \"table\", \"json\", or \"yaml\".",
				})
			}
		}

		c.flags = set
	})

	return c.flags
}

// printFlagTitle prints a consistently-formatted title to the given writer.
func printFlagTitle(w io.Writer, s string) {
	fmt.Fprintf(w, "%s\n\n", s)
}

// printFlagDetail prints a single flag to the given writer.
func printFlagDetail(w io.Writer, f *flag.Flag) {
	example := ""
	if t, ok := f.Value.(FlagExample); ok {
		example = t.Example()
	}

	if example != "" {
		fmt.Fprintf(w, "  -%s=<%s>\n", f.Name, example)
	} else {
		fmt.Fprintf(w, "  -%s\n", f.Name)
	}

	usage := reRemoveWhitespace.ReplaceAllString(f.Usage, " ")
	indented := wrapAtLength(usage, 6)
	fmt.Fprintf(w, "%s\n\n", indented)
}

// wrapAtLength wraps the given text at the maxLineLength, taking into account
// any provided left padding.
func wrapAtLength(s string, pad int) string {
	wrapped := text.Wrap(s, maxLineLength-pad)
	lines := strings.Split(wrapped, "\n")
	for i, line := range lines {
		lines[i] = strings.Repeat(" ", pad) + line
	}
	return strings.Join(lines, "\n")
}

// FlagSets is a group of flag sets.
type FlagSets struct {
	flagSets    []*FlagSet
	mainSet     *flag.FlagSet
	hiddens     map[string]struct{}
	completions complete.Flags
}

// NewFlagSets creates a new flag sets.
func NewFlagSets(ui cli.Ui) *FlagSets {
	mainSet := flag.NewFlagSet("", flag.ContinueOnError)
	mainSet.Usage = func() {}

	// Pull errors from the flagset into the ui's error
	errR, errW := io.Pipe()
	errScanner := bufio.NewScanner(errR)
	go func() {
		for errScanner.Scan() {
			ui.Error(errScanner.Text())
		}
	}()
	mainSet.SetOutput(errW)

	return &FlagSets{
		flagSets:    make([]*FlagSet, 0, 6),
		mainSet:     mainSet,
		hiddens:     make(map[string]struct{}),
		completions: complete.Flags{},
	}
}

// NewFlagSet creates a new flag set from the given flag sets.
func (f *FlagSets) NewFlagSet(name string) *FlagSet {
	flagSet := NewFlagSet(name)
	f.AddFlagSet(flagSet)
	return flagSet
}

// AddFlagSet adds a new flag set to this flag set.
func (f *FlagSets) AddFlagSet(set *FlagSet) {
	set.mainSet = f.mainSet
	set.completions = f.completions
	f.flagSets = append(f.flagSets, set)
}

func (f *FlagSets) Completions() complete.Flags {
	return f.completions
}

// Parse parses the given flags, returning any errors.
func (f *FlagSets) Parse(args []string) error {
	return f.mainSet.Parse(args)
}

// Args returns the remaining args after parsing.
func (f *FlagSets) Args() []string {
	return f.mainSet.Args()
}

// HideFlag excludes the flag from the list of flags to print in help. This is
// useful when you want to include a flag in parsing for deprecations/bc, but
// you don't want to include it in help output.
func (f *FlagSets) HideFlag(n string) {
	if _, ok := f.hiddens[n]; !ok {
		f.hiddens[n] = struct{}{}
	}
}

// HiddenFlag returns true if the flag with the given name is hidden.
func (f *FlagSets) HiddenFlag(n string) bool {
	_, ok := f.hiddens[n]
	return ok
}

// Help builds custom help for this command, grouping by flag set.
func (fs *FlagSets) Help() string {
	var out bytes.Buffer

	for _, set := range fs.flagSets {
		printFlagTitle(&out, set.name+":")
		set.VisitAll(func(f *flag.Flag) {
			// Skip any hidden flags
			if fs.HiddenFlag(f.Name) {
				return
			}
			printFlagDetail(&out, f)
		})
	}

	return strings.TrimRight(out.String(), "\n")
}

// FlagSet is a grouped wrapper around a real flag set and a grouped flag set.
type FlagSet struct {
	name        string
	flagSet     *flag.FlagSet
	mainSet     *flag.FlagSet
	completions complete.Flags
}

// NewFlagSet creates a new flag set.
func NewFlagSet(name string) *FlagSet {
	return &FlagSet{
		name:    name,
		flagSet: flag.NewFlagSet(name, flag.ContinueOnError),
	}
}

// Name returns the name of this flag set.
func (f *FlagSet) Name() string {
	return f.name
}

func (f *FlagSet) Visit(fn func(*flag.Flag)) {
	f.flagSet.Visit(fn)
}

func (f *FlagSet) VisitAll(fn func(*flag.Flag)) {
	f.flagSet.VisitAll(fn)
}
