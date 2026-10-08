package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/seal"
)

const maxSideBytes = 32 << 10

var (
	envName   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	ownFiles  = []string{"compose.krynodes.json", "compose.krynodes.previous.json", "compose.previous.yaml", "krynodes.json", ".env", ".env.previous"}
	keptNames = append(slices.Clone(ownFiles), standardComposeFiles...)
)

type composeFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type moveBundle struct {
	Env   map[string]string `json:"env,omitempty"`
	Files map[string][]byte `json:"files,omitempty"`
}

type composeRead struct {
	Compose string            `json:"compose"`
	Access  string            `json:"access"`
	Files   []composeFile     `json:"files"`
	Images  map[string]string `json:"images"`
}

func (e Executor) opened(sealed string, value any) error {
	key, err := e.sealKey()
	if err != nil {
		return err
	}
	plain, err := seal.Open(key, sealed)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func checkSecrets(values map[string]string) error {
	for _, name := range sortedKeys(anyMap(values)) {
		if !envName.MatchString(name) {
			return fmt.Errorf("secret name %q may hold letters, digits and _, not starting with a digit", name)
		}
		if strings.ContainsAny(values[name], "'\n\r\x00") {
			return fmt.Errorf("secret %s cannot contain ' or a line break", name)
		}
	}
	return nil
}

func anyMap(values map[string]string) map[string]any {
	found := make(map[string]any, len(values))
	for key, value := range values {
		found[key] = value
	}
	return found
}

func writeEnv(directory string, values map[string]string) error {
	var text strings.Builder
	for _, name := range sortedKeys(anyMap(values)) {
		fmt.Fprintf(&text, "%s='%s'\n", name, values[name])
	}
	if err := writeWhole(directory, ".env", []byte(text.String()), 0o600); err != nil {
		return err
	}
	return os.Chmod(filepath.Join(directory, ".env"), 0o600)
}

func readEnv(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
		name, value, found := strings.Cut(line, "=")
		if !found || strings.HasPrefix(line, "#") || !envName.MatchString(strings.TrimSpace(name)) {
			continue
		}
		value = strings.TrimSpace(value)
		switch {
		case len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'':
			value = value[1 : len(value)-1]
		case len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"':
			value = strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\n`, "\n").Replace(value[1 : len(value)-1])
		default:
			if comment := strings.Index(value, " #"); comment >= 0 {
				value = strings.TrimSpace(value[:comment])
			}
		}
		values[strings.TrimSpace(name)] = value
	}
	return values, nil
}

func sideFiles(directory string, composeFiles []string) ([]composeFile, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	files := []composeFile{}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || slices.Contains(ownFiles, name) || slices.ContainsFunc(composeFiles, func(file string) bool {
			return filepath.Base(file) == name && filepath.Clean(filepath.Dir(file)) == filepath.Clean(directory)
		}) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		files = append(files, composeFile{Name: name, Size: info.Size()})
	}
	return files, nil
}

func (e Executor) sourceFile(stack Stack) string {
	if e.ownStack(stack.Directory) {
		return filepath.Join(stack.Directory, "compose.yaml")
	}
	return stack.Files[0]
}

func (e Executor) pinned(ctx context.Context, stack Stack) map[string]string {
	images := map[string]string{}
	records, err := e.running(ctx, stack)
	if err != nil {
		return images
	}
	for _, record := range records {
		output, err := e.docker(ctx, collectTimeout, "inspect", "image", "inspect", "--format", "{{json .RepoDigests}}", record.ID)
		if err != nil {
			continue
		}
		var digests []string
		if json.Unmarshal(bytes.TrimSpace(output), &digests) != nil {
			continue
		}
		reference, _, _ := strings.Cut(record.Reference, "@")
		repository := reference
		if colon := strings.LastIndex(reference, ":"); colon > strings.LastIndex(reference, "/") {
			repository = reference[:colon]
		}
		for _, digest := range digests {
			if name, sum, found := strings.Cut(digest, "@"); found && name == repository {
				images[record.Service] = reference + "@" + sum
				break
			}
		}
	}
	return images
}

func (e Executor) read(ctx context.Context, request Request, stack Stack) Result {
	text, err := os.ReadFile(e.sourceFile(stack))
	if err != nil {
		return e.failed(request, err, "")
	}
	if len(text) > maxComposeBytes {
		return e.refuse(request.ID, errors.New("the compose file is larger than 32 KB"))
	}
	files, err := sideFiles(stack.Directory, append(slices.Clone(stack.Files), e.sourceFile(stack)))
	if err != nil {
		return e.failed(request, err, "")
	}
	output, err := json.Marshal(composeRead{Compose: string(text), Access: e.accessOf(stack.Directory), Files: files, Images: e.pinned(ctx, stack)})
	if err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: string(output), FinishedAt: e.stamp()}
}

func (e Executor) export(request Request, command Command, stack Stack) Result {
	key := command.Args["key"]
	if key == "" {
		return e.refuse(request.ID, errors.New("the export names no server key"))
	}
	env, err := readEnv(filepath.Join(stack.Directory, ".env"))
	if err != nil {
		return e.failed(request, err, "")
	}
	listed, err := sideFiles(stack.Directory, append(slices.Clone(stack.Files), e.sourceFile(stack)))
	if err != nil {
		return e.failed(request, err, "")
	}
	bundle := moveBundle{Env: env, Files: map[string][]byte{}}
	var total int64
	for _, file := range listed {
		if total += file.Size; total > maxSideBytes {
			return e.refuse(request.ID, errors.New("the files beside the compose file are larger than 32 KB together; recreate them on the target"))
		}
		body, err := os.ReadFile(filepath.Join(stack.Directory, file.Name))
		if err != nil {
			return e.failed(request, err, "")
		}
		bundle.Files[file.Name] = body
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		return e.failed(request, err, "")
	}
	sealed, err := seal.Seal(key, encoded)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	return Result{ID: request.ID, OK: true, Output: sealed, FinishedAt: e.stamp()}
}

func (e Executor) prepare(request Request, command Command, directory string) error {
	env := map[string]string{}
	if request.Attachment != "" {
		var bundle moveBundle
		if err := e.opened(request.Attachment, &bundle); err != nil {
			return fmt.Errorf("the moved files: %w", err)
		}
		for name, body := range bundle.Files {
			if name == "" || filepath.Base(name) != name || strings.HasPrefix(name, ".") || slices.Contains(keptNames, name) {
				return fmt.Errorf("a moved file may not be named %q", name)
			}
			if err := writeWhole(directory, name, body, 0o640); err != nil {
				return err
			}
		}
		for name, value := range bundle.Env {
			env[name] = value
		}
	}
	if command.Secrets != "" {
		var secrets map[string]string
		if err := e.opened(command.Secrets, &secrets); err != nil {
			return fmt.Errorf("the secrets: %w", err)
		}
		for name, value := range secrets {
			env[name] = value
		}
	}
	if len(env) == 0 {
		return nil
	}
	if err := checkSecrets(env); err != nil {
		return err
	}
	return writeEnv(directory, env)
}

func (e Executor) launch(ctx context.Context, request Request, name, directory, access, done string) Result {
	stack := Stack{Project: name, Directory: directory, Files: []string{filepath.Join(directory, "compose.yaml")}}
	output, err := e.docker(ctx, collectTimeout, "read", composeArgs(stack, "config", "--format", "json")...)
	if err != nil {
		return e.failed(request, err, "")
	}
	var config map[string]any
	start := bytes.IndexByte(output, '{')
	if start < 0 || json.Unmarshal(output[start:], &config) != nil {
		return e.refuse(request.ID, errors.New("compose did not return a readable file"))
	}
	if access == "contained" {
		if err := vet(config, directory); err != nil {
			return e.refuse(request.ID, err)
		}
		if err := e.checkRegistries(ctx, config); err != nil {
			return e.refuse(request.ID, err)
		}
		if err := contain(config, name); err != nil {
			return e.refuse(request.ID, err)
		}
		localPorts(config)
		if err := writeJSON(directory, "compose.krynodes.json", config, 0o640); err != nil {
			return e.failed(request, err, "")
		}
		stack.Files = []string{filepath.Join(directory, "compose.krynodes.json")}
	} else if err := os.Remove(filepath.Join(directory, "compose.krynodes.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return e.failed(request, err, "")
	}
	if err := e.fits(ctx, config); err != nil {
		return e.refuse(request.ID, err)
	}
	if _, err := e.docker(ctx, pullTimeout, "pull", composeArgs(stack, "pull")...); err != nil {
		return e.failed(request, err, "")
	}
	if _, err := e.docker(ctx, upTimeout, "up", composeArgs(stack, "up", "-d")...); err != nil {
		return e.failed(request, err, e.states(ctx, stack))
	}
	if states, err := e.healthy(ctx, stack); err != nil {
		return e.failed(request, err, states)
	}
	if err := writeJSON(directory, "krynodes.json", stackMeta{Access: access}, 0o640); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: done, FinishedAt: e.stamp()}
}

func accessFrom(command Command, fallback string) (string, error) {
	switch command.Access {
	case "":
		return fallback, nil
	case "contained", "full":
		return command.Access, nil
	}
	return "", fmt.Errorf("unknown access %q", command.Access)
}

func checkText(text, access string) error {
	switch {
	case strings.TrimSpace(text) == "":
		return errors.New("the compose file is empty")
	case len(text) > maxComposeBytes:
		return errors.New("the compose file is larger than 32 KB")
	case access == "contained" && includeLine.MatchString(text):
		return errors.New("include is not allowed; paste a single compose file")
	}
	return nil
}

func backup(directory string, names map[string]string) (func(), error) {
	moved := map[string]string{}
	restore := func() {
		for from, to := range moved {
			os.Remove(filepath.Join(directory, from))
			os.Rename(filepath.Join(directory, to), filepath.Join(directory, from))
		}
	}
	for from, to := range names {
		if err := copyFile(context.Background(), filepath.Join(directory, from), filepath.Join(directory, to)); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		moved[from] = to
	}
	return func() {
		restore()
	}, nil
}

func copyFile(ctx context.Context, from, to string) error {
	source, err := os.Open(from)
	if err != nil {
		return err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return err
	}
	target, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(target, contextReader{ctx, source}); err != nil {
		target.Close()
		return err
	}
	return target.Close()
}

func (e Executor) edit(ctx context.Context, request Request, command Command, stack Stack) Result {
	if !e.ownStack(stack.Directory) {
		return e.refuse(request.ID, errors.New("only stacks Krynodes made can be edited; use Move into Krynodes first"))
	}
	current := e.accessOf(stack.Directory)
	access, err := accessFrom(command, current)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	if err := checkText(command.Compose, access); err != nil {
		return e.refuse(request.ID, err)
	}
	directory := stack.Directory
	previous := map[string]string{"compose.yaml": "compose.previous.yaml", "compose.krynodes.json": "compose.krynodes.previous.json"}
	if command.Secrets != "" {
		previous[".env"] = ".env.previous"
	}
	restore, err := backup(directory, previous)
	if err != nil {
		return e.failed(request, err, "")
	}
	revert := func(result Result) Result {
		restore()
		old := Stack{Project: stack.Project, Directory: directory, Files: []string{filepath.Join(directory, "compose.yaml")}}
		if current == "contained" {
			old.Files = []string{filepath.Join(directory, "compose.krynodes.json")}
		}
		e.docker(ctx, upTimeout, "up", composeArgs(old, "up", "-d")...)
		return result
	}
	if err := writeWhole(directory, "compose.yaml", []byte(command.Compose), 0o640); err != nil {
		return revert(e.failed(request, err, ""))
	}
	if command.Secrets != "" {
		if err := e.prepare(request, Command{Secrets: command.Secrets}, directory); err != nil {
			return revert(e.refuse(request.ID, err))
		}
	}
	result := e.launch(ctx, request, stack.Project, directory, access, "updated")
	if !result.OK {
		return revert(result)
	}
	return result
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (c contextReader) Read(buffer []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.reader.Read(buffer)
}

func copyTree(ctx context.Context, from, to string) error {
	return filepath.WalkDir(from, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		target := filepath.Join(to, relative)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			if err := os.MkdirAll(target, info.Mode().Perm()); err != nil {
				return err
			}
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if err := os.Symlink(link, target); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			if err := copyFile(ctx, path, target); err != nil {
				return err
			}
		default:
			return nil
		}
		if uid, gid, ok := owner(info); ok {
			if err := os.Lchown(target, uid, gid); err != nil {
				return err
			}
		}
		return nil
	})
}

func treeSize(root string) uint64 {
	var total uint64
	filepath.WalkDir(root, func(_ string, entry fs.DirEntry, err error) error {
		if err == nil && entry.Type().IsRegular() {
			if info, err := entry.Info(); err == nil {
				total += uint64(info.Size())
			}
		}
		return nil
	})
	return total
}

func (e Executor) adopt(ctx context.Context, request Request, stack Stack) Result {
	if e.ownStack(stack.Directory) {
		return e.refuse(request.ID, fmt.Errorf("%s is already in Krynodes", stack.Project))
	}
	target := filepath.Join(e.StateDir, "compose", stack.Project)
	if _, err := os.Lstat(target); err == nil || e.waiting(stack.Project) {
		return e.refuse(request.ID, fmt.Errorf("Krynodes already has a stack named %s", stack.Project))
	}
	if available, err := e.freeSpace(e.StateDir); err == nil {
		if want := treeSize(stack.Directory) + diskReserve; want > available {
			return e.refuse(request.ID, fmt.Errorf("the folder needs about %s with room to spare; the server has %s free", gigabytes(want), gigabytes(available)))
		}
	}
	moved := Stack{Project: stack.Project, Directory: target}
	for _, file := range stack.Files {
		if within(stack.Directory, file) {
			relative, _ := filepath.Rel(stack.Directory, file)
			file = filepath.Join(target, relative)
		}
		moved.Files = append(moved.Files, file)
	}
	if _, err := e.docker(ctx, upTimeout, "down", composeArgs(stack, "down")...); err != nil {
		return e.failed(request, err, "")
	}
	back := func(result Result) Result {
		os.RemoveAll(target)
		e.docker(ctx, upTimeout, "up", composeArgs(stack, "up", "-d")...)
		return result
	}
	copying, cancel := context.WithTimeout(ctx, copyTimeout)
	err := copyTree(copying, stack.Directory, target)
	cancel()
	if errors.Is(err, context.DeadlineExceeded) {
		err = fmt.Errorf("copying %s took longer than %d minutes; it runs from its old folder again, move its data by hand", stack.Directory, int(copyTimeout.Minutes()))
	}
	if err != nil {
		return back(e.failed(request, err, ""))
	}
	if _, err := e.docker(ctx, upTimeout, "up", composeArgs(moved, "up", "-d")...); err != nil {
		e.docker(ctx, upTimeout, "down", composeArgs(moved, "down")...)
		return back(e.failed(request, err, e.states(ctx, moved)))
	}
	if states, err := e.healthy(ctx, moved); err != nil {
		e.docker(ctx, upTimeout, "down", composeArgs(moved, "down")...)
		return back(e.failed(request, err, states))
	}
	if err := writeJSON(target, "krynodes.json", stackMeta{Access: "full"}, 0o640); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: "moved into Krynodes; the old folder " + stack.Directory + " stays", FinishedAt: e.stamp()}
}
