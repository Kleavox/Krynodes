package store

import (
	"bytes"
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
	folderSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	fileSDDL   = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	suffix     = ".dpapi"
	logLimit   = 1 << 20
)

type Store struct {
	Dir  string
	file string
}

func Dir() (string, error) {
	data, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(data, "Krynodes"), nil
}

func Open(dir string) (Store, error) {
	if err := create(dir, folderSDDL); err != nil {
		return Store{}, err
	}
	return Store{Dir: dir, file: fileSDDL}, nil
}

func create(dir, sddl string) error {
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	if err := windows.CreateDirectory(path, &attributes); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	return lock(dir, sddl, true)
}

func (s Store) Lock(name string) error {
	return lock(filepath.Join(s.Dir, name), s.file, false)
}

func (s Store) Put(name string, value []byte) error {
	sealed, err := protect(value)
	if err != nil {
		return err
	}
	path := filepath.Join(s.Dir, name+suffix)
	if err := safefile.Write(path, sealed, 0o600); err != nil {
		return err
	}
	return lock(path, s.file, false)
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
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
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
	if !trusted(found, owner) {
		return refused
	}
	return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil)
}

func trusted(found, owner *windows.SID) bool {
	if found.Equals(owner) {
		return true
	}
	for _, kind := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		if sid, err := windows.CreateWellKnownSid(kind); err == nil && found.Equals(sid) {
			return true
		}
	}
	return false
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
	return &Log{path: filepath.Join(s.Dir, name), sddl: s.file, limit: logLimit}
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
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
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
