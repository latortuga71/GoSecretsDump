package win32

import "syscall"

var (
	ModKernel32        = syscall.NewLazyDLL("kernel32.dll")
	VirtualProtect     = ModKernel32.NewProc("VirtualProtect")
	VirtualProtectEx   = ModKernel32.NewProc("VirtualProtectEx")
	HeapAlloc          = ModKernel32.NewProc("HeapAlloc")
	HeapFree           = ModKernel32.NewProc("HeapFree")
	VirtualAlloc       = ModKernel32.NewProc("VirtualAlloc")
	VirtualAllocEx     = ModKernel32.NewProc("VirtualAllocEx")
	WriteProcessMemory = ModKernel32.NewProc("WriteProcessMemory")
	ReadProcessMemory  = ModKernel32.NewProc("ReadProcessMemory")
	CreateThread       = ModKernel32.NewProc("CreateThread")
	CreateRemoteThread = ModKernel32.NewProc("CreateRemoteThread")
	GetCurrentProcess  = ModKernel32.NewProc("GetCurrentProcess")
)
