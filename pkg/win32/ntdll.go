package win32

import "syscall"

var (
	ModNtdll = syscall.NewLazyDLL("ntdll.dll")
)
