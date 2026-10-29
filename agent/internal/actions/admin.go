package actions

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/recipes"
	"github.com/Kleavox/krynodes/agent/internal/watch"
)

const (
	adminFile     = "admin-user.json"
	adminMarkFile = "admin-mark.json"
	adminWindow   = 30 * time.Minute
	maxAdminKeys  = 4
)

var errAdminAgain = errors.New("Open this server in Krynodes, choose Actions → Add Admin User and run the command it gives within 30 minutes.")

type adminTicket struct {
	ID    string    `json:"id"`
	Name  string    `json:"name"`
	Keys  []string  `json:"keys"`
	Until time.Time `json:"until"`
}

type adminMark struct {
	Name  string    `json:"name"`
	Keys  []string  `json:"keys"`
	Until time.Time `json:"until"`
}

func (e Executor) markAdmin(name string, keys []recipes.AdminKey) func() {
	mark := adminMark{Name: name, Until: e.Now().Add(adminWindow)}
	for _, key := range keys {
		mark.Keys = append(mark.Keys, key.Fingerprint())
	}
	writeJSON(e.StateDir, adminMarkFile, mark, 0o600)
	return func() { os.Remove(filepath.Join(e.StateDir, adminMarkFile)) }
}

func (mark adminMark) covers(now time.Time, change watch.Change) bool {
	if mark.Name == "" || !now.Before(mark.Until) {
		return false
	}
	switch change.Kind {
	case "user":
		return change.Item == mark.Name
	case "sudo":
		parts := strings.SplitN(change.Item, ":", 3)
		return len(parts) == 3 && parts[0] == "group" && parts[2] == mark.Name
	case "ssh-key":
		return strings.HasPrefix(change.Item, mark.Name+":") && slices.ContainsFunc(mark.Keys, func(print string) bool {
			return strings.HasSuffix(change.Item, ":"+print)
		})
	}
	return false
}

func parseAdminKeys(list []string) ([]recipes.AdminKey, error) {
	if len(list) == 0 || len(list) > maxAdminKeys {
		return nil, fmt.Errorf("an admin user takes one to %d SSH keys", maxAdminKeys)
	}
	keys := make([]recipes.AdminKey, 0, len(list))
	for _, arg := range list {
		key, err := recipes.ParseAdminKey(arg)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (e Executor) adminExpect(request Request) Result {
	command, err := e.authorize(request)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	name, list := command.Args["name"], strings.Split(command.Args["keys"], ",")
	if len(command.Args) != 2 || !recipes.ValidAdminName(name) {
		return e.refuse(request.ID, errors.New("an admin user needs a name such as musyaf, not root, and its SSH keys"))
	}
	if _, err := parseAdminKeys(list); err != nil {
		return e.refuse(request.ID, err)
	}
	if err := writeJSON(e.StateDir, adminFile, adminTicket{ID: request.ID, Name: name, Keys: list, Until: e.Now().Add(adminWindow)}, 0o600); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: "ready: run sudo kry admin-user " + name + " on this server within 30 minutes", FinishedAt: e.stamp()}
}

func (e Executor) addAdmin(ctx context.Context, name string, keys []recipes.AdminKey, tty recipes.Terminal, mark func(sign, title, rest string)) (recipes.AdminResult, bool) {
	result, err := recipes.AddAdmin(ctx, e.recipeEnv(), name, keys, tty)
	var skipped recipes.AdminSkipped
	switch {
	case errors.As(err, &skipped):
		mark("–", "Admin user", " skipped: "+err.Error())
	case err != nil:
		mark("✗", "Admin user "+name, ": "+err.Error())
	default:
		mark("✓", "Admin user "+name, " · sudo with its password")
	}
	return result, err == nil
}

func (e Executor) noRootLogin(ctx context.Context, name string, mark func(sign, title, rest string)) {
	const title = "No root login"
	state := e.readRecipes()
	if _, on := state.Applied["no-root-login"]; on {
		mark("–", title, " already on")
		return
	}
	if !slices.Contains(recipes.SSHLogins(ctx, e.recipeEnv()), name) {
		mark("–", title, " skipped: "+name+" cannot log in over SSH with a key yet")
		return
	}
	e.applyRecipe(ctx, state, "no-root-login", nil, title, " · log in as "+name+" from now on", mark)
}

func (e Executor) applyRecipe(ctx context.Context, state recipeState, id string, args map[string]string, title, rest string, mark func(sign, title, rest string)) {
	saved, err := recipes.Apply(ctx, e.recipeEnv(), id, args)
	if err == nil {
		state.Applied[id] = appliedRecipe{At: e.Now(), Saved: saved}
		err = writeJSON(e.StateDir, "recipes.json", state, 0o640)
	}
	if err != nil {
		mark("✗", title, ": "+err.Error())
		return
	}
	mark("✓", title, rest)
}

func (e Executor) AdminUser(ctx context.Context, name string, out io.Writer, tty recipes.Terminal) error {
	ticket, err := readState[adminTicket](e.StateDir, adminFile)
	if err != nil || ticket.Name != name || !e.Now().Before(ticket.Until) {
		return errAdminAgain
	}
	keys, err := parseAdminKeys(ticket.Keys)
	if err != nil {
		return errAdminAgain
	}
	defer e.markAdmin(name, keys)()
	defer os.Remove(filepath.Join(e.StateDir, "security.json"))
	mark := func(sign, title, rest string) {
		fmt.Fprintf(out, "%s %s%s\n", sign, title, rest)
	}
	result, made := e.addAdmin(ctx, name, keys, tty, mark)
	if result.Group != "" {
		e.acceptAdmin(name, result, keys)
	}
	if !made {
		return nil
	}
	os.Remove(filepath.Join(e.StateDir, adminFile))
	if state := e.readRecipes(); state.Applied["ssh-keys-only"].At.IsZero() {
		e.applyRecipe(ctx, state, "ssh-keys-only", nil, "SSH keys only", "", mark)
	} else {
		mark("–", "SSH keys only", " already on")
	}
	e.noRootLogin(ctx, name, mark)
	return nil
}

func (e Executor) acceptAdmin(name string, result recipes.AdminResult, keys []recipes.AdminKey) {
	start, err := readState[watch.State](e.StateDir, watchFile)
	if err != nil {
		return
	}
	start.Accept("user", name)
	start.Accept("sudo", "group:"+result.Group+":"+name)
	for _, file := range result.KeyFiles {
		for _, key := range keys {
			start.Accept("ssh-key", name+":"+file+":"+key.Fingerprint())
		}
	}
	writeJSON(e.StateDir, watchFile, start, 0o640)
}
