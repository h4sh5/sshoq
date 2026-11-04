package internal

import (
	"errors"
	"net/http"
	"testing"

	"github.com/h4sh5/sshoq/auth"
	client_config "github.com/h4sh5/sshoq/client/config"
	"github.com/h4sh5/sshoq/util"
)

// The plugin registry, which is where the set of things that may authenticate a user comes from.
//
// `auth/plugins` is the extension point: a plugin package registers a `ServerAuthPlugin` from its `init()`,
// the server closes the registry once the binary has started, and every `authorized_keys` identity line is
// then offered to every registered plugin, whose returned verifier is what `CheckRequest` and the login
// path eventually consult. Three rules decide who is in that set, and none of them was written down in
// `proof/SECURITY_REQUIREMENTS.md` or tested anywhere -- **F12**:
//
//   * registration after the close is refused, with `util.ClosedPluginsRegistry`, so a plugin cannot join
//     the authentication path while the server is serving;
//   * a duplicate name fails loudly -- the registry panics -- and, because it panics *before* writing to
//     the map, the plugin already registered under that name is the one that survives;
//   * a plugin that returns an error, or returns no identity for a line it does not recognise, adds
//     nothing to the identity list: it does not veto the others and it is not itself a way to authenticate.
//
// The third is the one worth a sentence: the registry is *not* where fail-closed lives. An identity is only
// honoured because a verifier the plugin returned accepts it; a broken plugin contributes an empty set, and
// an empty set authenticates nobody. What the tests below pin is that the plumbing around that promise
// cannot quietly widen it.

// conformanceVerifier is a verifier with a label, so a test can tell which plugin produced it.
type conformanceVerifier struct {
	label  string
	accept bool
}

func (v conformanceVerifier) Verify(r *http.Request, base64ConversationID string) bool {
	return v.accept
}

// conformancePlugin returns a server auth plugin that yields a verifier carrying the given label, or the
// given error, or nothing at all -- the three things a real plugin can do with an identity line.
func conformancePlugin(label string, err error) auth.ServerAuthPlugin {
	return func(username string, identityStr string) (auth.RequestIdentityVerifier, error) {
		if err != nil {
			return nil, err
		}
		if label == "" {
			return nil, nil
		}
		return conformanceVerifier{label: label, accept: true}, nil
	}
}

// conformanceLabels lists the labels of the verifiers an identity search returned, so a test can compare
// sets without depending on Go's map iteration order.
func conformanceLabels(identities []auth.RequestIdentityVerifier) []string {
	out := []string{}
	for _, id := range identities {
		if v, ok := id.(conformanceVerifier); ok {
			out = append(out, v.label)
		} else {
			out = append(out, "<foreign>")
		}
	}
	return out
}

func conformanceHasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

// TestConformanceRegistrationIsRefusedAfterClose is the first rule: once the registry is closed -- which is
// what the server does before it accepts a connection -- a registration is an error and changes nothing.
func TestConformanceRegistrationIsRefusedAfterClose(t *testing.T) {
	r := newPluginsRegistry[auth.ServerAuthPlugin]()
	if err := r.registerPlugin("first", conformancePlugin("first", nil)); err != nil {
		t.Fatalf("a fresh registry must accept a registration: %v", err)
	}
	r.closeRegistry()

	err := r.registerPlugin("late", conformancePlugin("late", nil))
	if err == nil {
		t.Fatal("a registration after the close was accepted: the authentication plugin set would be open at serve time")
	}
	var closed util.ClosedPluginsRegistry
	if !errors.As(err, &closed) {
		t.Errorf("the refusal is %q of type %T, want util.ClosedPluginsRegistry", err, err)
	}
	if len(r.plugins) != 1 {
		t.Fatalf("the refused registration changed the registry: %d plugins, want the 1 registered before the close", len(r.plugins))
	}
	if _, ok := r.plugins["late"]; ok {
		t.Error("the refused registration is in the map anyway")
	}
	// closing twice is not an error in itself, and does not reopen anything
	r.closeRegistry()
	if len(r.plugins) != 1 {
		t.Fatalf("closing twice changed the registry: %d plugins", len(r.plugins))
	}
	if err := r.registerPlugin("later", conformancePlugin("later", nil)); err == nil {
		t.Error("a closed registry reopened")
	}
}

// TestConformanceDuplicateNameFailsLoudlyAndKeepsTheFirstPlugin is the second rule, and the direction that
// matters: the panic happens before the map write, so a collision cannot replace the plugin that got there
// first. A registry that panicked *after* writing would leave a process crash and, on restart, a different
// meaning for the same identity line.
func TestConformanceDuplicateNameFailsLoudlyAndKeepsTheFirstPlugin(t *testing.T) {
	r := newPluginsRegistry[auth.ServerAuthPlugin]()
	if err := r.registerPlugin("dup", conformancePlugin("first", nil)); err != nil {
		t.Fatalf("registering the first plugin: %v", err)
	}

	panicked := func() (p any) {
		defer func() { p = recover() }()
		_ = r.registerPlugin("dup", conformancePlugin("second", nil))
		return nil
	}()
	if panicked == nil {
		t.Fatal("a duplicate plugin name was accepted silently; two plugins would answer the same identity line")
	}
	got, ok := r.plugins["dup"]
	if !ok {
		t.Fatal("the colliding registration removed the plugin registered under that name")
	}
	verifier, err := got("user", "identity")
	if err != nil {
		t.Fatalf("the surviving plugin errors: %v", err)
	}
	v, ok := verifier.(conformanceVerifier)
	if !ok || v.label != "first" {
		t.Errorf("after a name collision the surviving plugin is %v, want the one registered first", verifier)
	}

	// a different name still registers after the collision, which is to say the registry is not left
	// wedged by the panic -- the mutex is released before it unwinds
	if err := r.registerPlugin("other", conformancePlugin("other", nil)); err != nil {
		t.Errorf("the registry is unusable after a colliding registration: %v", err)
	}
}

// TestConformanceNilRegistryPanics documents the third guard: there is no registry to write to. It is a
// panic rather than an error because it is a programming mistake in a plugin, and the alternative is a
// plugin that silently never authenticates anybody.
func TestConformanceNilRegistryPanics(t *testing.T) {
	var r *pluginsRegistry[auth.ServerAuthPlugin]
	got := func() (p any) {
		defer func() { p = recover() }()
		_ = r.registerPlugin("x", conformancePlugin("x", nil))
		return nil
	}()
	if got == nil {
		t.Error("a nil registry accepted a registration")
	}
	empty := newPluginsRegistry[auth.ServerAuthPlugin]()
	empty.plugins = nil
	got = func() (p any) {
		defer func() { p = recover() }()
		_ = empty.registerPlugin("x", conformancePlugin("x", nil))
		return nil
	}()
	if got == nil {
		t.Error("a registry with a nil map accepted a registration")
	}
}

// conformanceWithServerRegistry swaps the global server registry's contents for the duration of a test,
// because FindIdentitiesFromAuthorizedIdentityString reads that global and nothing else.
func conformanceWithServerRegistry(t *testing.T, plugins map[string]auth.ServerAuthPlugin) {
	t.Helper()
	savedPlugins := serverRegistry.plugins
	savedOpen := serverRegistry.registrationsOpen
	t.Cleanup(func() {
		serverRegistry.plugins = savedPlugins
		serverRegistry.registrationsOpen = savedOpen
	})
	serverRegistry.plugins = plugins
	serverRegistry.registrationsOpen = true
}

// TestConformanceIdentitySearchIsFailClosed is the promise behind the third rule: an identity comes from a
// plugin that returned one, and from nothing else. A plugin that errors is skipped -- it does not veto the
// search, and it does not become an identity -- and a plugin that recognises nothing returns a nil
// verifier, which is likewise not an identity. An empty registry yields no way to authenticate.
func TestConformanceIdentitySearchIsFailClosed(t *testing.T) {
	conformanceWithServerRegistry(t, map[string]auth.ServerAuthPlugin{})
	if ids := FindIdentitiesFromAuthorizedIdentityString("user", "any line"); len(ids) != 0 {
		t.Fatalf("an empty registry yielded %d identities: nobody is authenticable by nothing", len(ids))
	}

	conformanceWithServerRegistry(t, map[string]auth.ServerAuthPlugin{
		"broken":  conformancePlugin("broken", errors.New("plugin is broken")),
		"unknown": conformancePlugin("", nil),
		"good":    conformancePlugin("good", nil),
	})
	// map iteration order is random, so the broken plugin is sometimes visited before the good one and
	// sometimes after; the answer must not depend on that.
	for i := 0; i < 50; i++ {
		labels := conformanceLabels(FindIdentitiesFromAuthorizedIdentityString("user", "any line"))
		if len(labels) != 1 || !conformanceHasLabel(labels, "good") {
			t.Fatalf("iteration %d: the identity search returned %v, want exactly the one plugin that produced a verifier", i, labels)
		}
	}
}

// conformanceOption is the smallest thing that satisfies client_config.CLIOptionParser, so the client
// registry's own collision rule can be exercised.
type conformanceOption string

func (o conformanceOption) OptionConfigName() string                            { return string(o) }
func (o conformanceOption) Parse(values []string) (client_config.Option, error) { return nil, nil }
func (o conformanceOption) FlagName() string                                    { return string(o) }
func (o conformanceOption) Usage() string                                       { return "test option " + string(o) }
func (o conformanceOption) IsBoolFlag() bool                                    { return false }

// TestConformanceClientOptionNamesCannotCollide is the same no-shadowing rule on the client side, where it
// is an error rather than a panic: two plugins offering the same config keyword refuse the configuration
// instead of letting the second one win, and they return no half-built option map to be used anyway.
func TestConformanceClientOptionNamesCannotCollide(t *testing.T) {
	saved := clientRegistry.plugins
	t.Cleanup(func() { clientRegistry.plugins = saved })

	clientRegistry.plugins = map[string]auth.ClientAuthPlugin{
		"a": {PluginOptions: map[client_config.OptionName]client_config.OptionParser{
			"keyword": conformanceOption("keyword"),
		}},
		"b": {PluginOptions: map[client_config.OptionName]client_config.OptionParser{
			"other": conformanceOption("other"),
		}},
	}
	args, err := GetPluginsCLIArgs()
	if err != nil {
		t.Fatalf("two plugins with different option names: %v", err)
	}
	if len(args) != 2 {
		t.Fatalf("two distinct options yielded %d entries, want 2", len(args))
	}

	clientRegistry.plugins["c"] = auth.ClientAuthPlugin{PluginOptions: map[client_config.OptionName]client_config.OptionParser{
		"keyword": conformanceOption("shadow"),
	}}
	args, err = GetPluginsCLIArgs()
	if err == nil {
		t.Fatal("a second plugin offering the same config keyword was accepted: one plugin would silently own another's option")
	}
	if args != nil {
		t.Errorf("the refusal returned a half-built map of %d entries, want nil", len(args))
	}
	parsers, err := GetPluginsClientOptionsParsers()
	if err == nil {
		t.Error("GetPluginsClientOptionsParsers accepted the colliding option name")
	}
	if parsers != nil {
		t.Errorf("the refusal returned %d parsers, want nil", len(parsers))
	}
}
