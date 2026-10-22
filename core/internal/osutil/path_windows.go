//go:build windows

package osutil

import (
	"path/filepath"
	"syscall"
	"unsafe"
)

var procExpandEnvironmentStringsW = kernel32.NewProc("ExpandEnvironmentStringsW")

// systemPathEntries reads the machine then the user PATH from the registry,
// with %VARIABLES% expanded, as a new console would see them.
func systemPathEntries() []string {
	var entries []string
	for _, source := range []struct {
		root syscall.Handle
		key  string
	}{
		{syscall.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`},
		{syscall.HKEY_CURRENT_USER, `Environment`},
	} {
		if value := registryString(source.root, source.key, "Path"); value != "" {
			entries = append(entries, filepath.SplitList(value)...)
		}
	}
	return entries
}

func registryString(root syscall.Handle, path, name string) string {
	keyName, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	var key syscall.Handle
	if syscall.RegOpenKeyEx(root, keyName, 0, syscall.KEY_READ, &key) != nil {
		return ""
	}
	defer syscall.RegCloseKey(key)
	valueName, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return ""
	}
	var kind, size uint32
	if syscall.RegQueryValueEx(key, valueName, nil, &kind, nil, &size) != nil || size == 0 {
		return ""
	}
	buffer := make([]uint16, size/2+1)
	if syscall.RegQueryValueEx(key, valueName, nil, &kind, (*byte)(unsafe.Pointer(&buffer[0])), &size) != nil {
		return ""
	}
	value := syscall.UTF16ToString(buffer)
	if kind != syscall.REG_EXPAND_SZ {
		return value
	}
	source, err := syscall.UTF16PtrFromString(value)
	if err != nil {
		return value
	}
	expanded := make([]uint16, 32*1024)
	r1, _, _ := procExpandEnvironmentStringsW.Call(uintptr(unsafe.Pointer(source)), uintptr(unsafe.Pointer(&expanded[0])), uintptr(len(expanded)))
	n := int(r1)
	if n == 0 || n > len(expanded) {
		return value
	}
	return syscall.UTF16ToString(expanded[:n])
}
