package store

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Kleavox/krynodes/agent/internal/safefile"
)

const (
	suffix   = ".dpapi"
	logLimit = 1 << 20
)

type Store struct {
	Dir   string
	owner string
}

func Dir() (string, error) {
	data, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(data, "Krynodes"), nil
}

func Open(dir string) (Store, error) {
	mine := owner()
	if err := create(dir, descriptor(mine, true, false)); err != nil {
		return Store{}, err
	}
	return Store{Dir: dir, owner: mine}, nil
}

func ProgramFolder(dir string) error {
	return create(dir, descriptor(owner(), true, true))
}

func ProgramFile(path string, data []byte) error {
	return write(path, data, descriptor(owner(), false, true))
}

func owner() string {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return administrators
	}
	return ownerFor(user.User.Sid.String())
}

func attributes(sddl string) (*windows.SecurityAttributes, error) {
	parsed, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: parsed}, nil
}

func create(dir, sddl string) error {
	security, err := attributes(sddl)
	if err != nil {
		return err
	}
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(path, security); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	return lock(dir, sddl, true)
}

func write(path string, data []byte, sddl string) error {
	security, err := attributes(sddl)
	if err != nil {
		return err
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+hex.EncodeToString(random)+".tmp")
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(from, windows.GENERIC_WRITE, 0, security, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), temporary)
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	if closed := file.Close(); err == nil {
		err = closed
	}
	if err == nil {
		err = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
	}
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return lock(path, sddl, false)
}

func (s Store) Write(path string, data []byte) error {
	return write(path, data, descriptor(s.owner, false, false))
}

func (s Store) Put(name string, value []byte) error {
	sealed, err := protect(value)
	if err != nil {
		return err
	}
	return s.Write(filepath.Join(s.Dir, name+suffix), sealed)
}

func (s Store) Get(name string) ([]byte, error) {
	sealed, err := safefile.Read(filepath.Join(s.Dir, name+suffix), 1<<16)
	if err != nil {
		return nil, err
	}
	return unprotect(sealed)
}

func protect(plain []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptProtectData(blob(plain), nil, nil, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return take(out), nil
}

func unprotect(sealed []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(sealed), nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return take(out), nil
}

func blob(data []byte) *windows.DataBlob {
	if len(data) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
}

func take(out windows.DataBlob) []byte {
	if out.Data == nil {
		return []byte{}
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return bytes.Clone(unsafe.Slice(out.Data, out.Size))
}

func lock(path, sddl string, directory bool) error {
	parsed, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := parsed.DACL()
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	refused := fmt.Errorf("%s was not made by Krynodes; delete it as an administrator and run install again", path)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	isDirectory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || isDirectory != directory || (!directory && info.NumberOfLinks != 1) {
		return refused
	}
	current, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	found, _, err := current.Owner()
	if err != nil {
		return err
	}
	if !trusted(found.String()) {
		return refused
	}
	return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

type Log struct {
	path  string
	sddl  string
	limit int64
	mu    sync.Mutex
	file  *os.File
	size  int64
}

func (s Store) Log(name string) *Log {
	return &Log{path: filepath.Join(s.Dir, name), sddl: descriptor(s.owner, false, false), limit: logLimit}
}

func (l *Log) Write(line []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil || l.size+int64(len(line)) > l.limit {
		if err := l.open(); err != nil {
			return 0, err
		}
	}
	written, err := l.file.Write(line)
	l.size += int64(written)
	return written, err
}

func (l *Log) open() error {
	if l.file != nil {
		l.file.Close()
		l.file = nil
		if err := os.Rename(l.path, l.path+".1"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	security, err := attributes(l.sddl)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(l.path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.FILE_APPEND_DATA|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, security, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), l.path)
	if err := lock(l.path, l.sddl, false); err != nil {
		file.Close()
		return err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	l.file, l.size = file, info.Size()
	if l.size >= l.limit {
		return l.open()
	}
	return nil
}
