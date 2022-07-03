package win32

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ModAdvapi32              = syscall.NewLazyDLL("advapi32.dll")
	pImpersonateLoggedOnUser = ModAdvapi32.NewProc("ImpersonateLoggedOnUser")
	pLogonUser               = ModAdvapi32.NewProc("LogonUserW")
	pRegConnectRegistry      = ModAdvapi32.NewProc("RegConnectRegistryW")
	pRegSaveKeyExW           = ModAdvapi32.NewProc("RegSaveKeyExW")
)

func RegSaveKeyExW(hKey windows.Handle, outFile string, lpsecuityAttributes uintptr, flags uint32) error {
	outfilePtr := syscall.StringToUTF16Ptr(outFile)
	res, _, err := pRegSaveKeyExW.Call(uintptr(hKey), uintptr(unsafe.Pointer(outfilePtr)), 0, uintptr(flags))
	if res != 0 {
		return err
	}
	return nil
}

func RegConnectRegistryW(host string, hKey windows.Handle, phKey *windows.Handle) bool {
	hostPtr := syscall.StringToUTF16Ptr(host)
	res, _, _ := pRegConnectRegistry.Call(uintptr(unsafe.Pointer(hostPtr)), uintptr(hKey), uintptr(unsafe.Pointer(phKey)))
	if res != 0 || *phKey == 0 {
		return false
	}
	return true
}
func ImpersonateLoggedOnUser(token windows.Token) (bool, error) {
	worked, _, err := pImpersonateLoggedOnUser.Call(uintptr(token))
	if worked == 0 {
		return false, err
	}
	return true, nil
}

func LogonUser(user string, domain string, password string, logonType uint32, logonProvider uint32, hToken *syscall.Handle) (bool, error) {
	userPtr := syscall.StringToUTF16Ptr(user)
	domainPtr := syscall.StringToUTF16Ptr(domain)
	passPtr := syscall.StringToUTF16Ptr(password)
	res, _, err := pLogonUser.Call(uintptr(unsafe.Pointer(userPtr)), uintptr(unsafe.Pointer(domainPtr)), uintptr(unsafe.Pointer(passPtr)), uintptr(logonType), uintptr(logonProvider), uintptr(unsafe.Pointer(hToken)))
	if res == 0 {
		return false, err
	}
	return true, nil
}
