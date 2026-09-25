//go:build windows

package localuser

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"rostor.org/app/cmd/rostor-deputy/internal/ledger"
)

// netapi32 constants (lmaccess.h). Only what contract §3 needs.
const (
	userPrivUser = 1

	ufScript           = 0x0001
	ufAccountDisable   = 0x0002
	ufDontExpirePasswd = 0x10000
	ufNormalAccount    = 0x0200
	nerrSuccess        = 0
	nerrUserNotFound   = 2221
	errorMemberInAlias = 1378
)

var (
	netapi32                    = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserAdd              = netapi32.NewProc("NetUserAdd")
	procNetUserGetInfo          = netapi32.NewProc("NetUserGetInfo")
	procNetUserSetInfo          = netapi32.NewProc("NetUserSetInfo")
	procNetLocalGroupAddMembers = netapi32.NewProc("NetLocalGroupAddMembers")
	procNetApiBufferFree        = netapi32.NewProc("NetApiBufferFree")
)

type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

type userInfo1003 struct{ Password *uint16 }
type userInfo1008 struct{ Flags uint32 }
type userInfo1011 struct{ FullName *uint16 }
type localgroupMembersInfo3 struct{ DomainAndName *uint16 }

// NetAPI is the Windows Manager: netapi32 calls gated by the ledger.
type NetAPI struct {
	Ledger *ledger.Ledger
	Logger *log.Logger
}

var _ Manager = (*NetAPI)(nil)

// EnsureEnabled implements Manager.
func (n *NetAPI) EnsureEnabled(username, displayName string) (string, error) {
	flags, exists, err := getFlags(username)
	if err != nil {
		return "", err
	}
	if exists && !n.Ledger.Has(username) {
		// A local account with this name predates Rostor. Refusing is the
		// only safe answer: rotating its password would lock a real person
		// out of an account we do not own.
		return "", ErrNotManaged
	}

	secret, err := NewSecret()
	if err != nil {
		return "", err
	}

	if !exists {
		if err := userAdd(username, secret, displayName); err != nil {
			return "", err
		}
		// Record before anything else can fail so a half-created account is
		// still ours to fix on the next attempt.
		if err := n.Ledger.Add(username); err != nil {
			return "", fmt.Errorf("ledger: %w", err)
		}
		if err := setFullName(username, displayName); err != nil {
			n.logf("set full name for %q: %v", username, err)
		}
		if err := addToUsersGroup(username); err != nil {
			return "", err
		}
		n.logf("created local account %q", username)
		return secret, nil
	}

	if err := setPassword(username, secret); err != nil {
		return "", err
	}
	if flags&ufAccountDisable != 0 {
		if err := setFlags(username, flags&^ufAccountDisable); err != nil {
			return "", err
		}
		n.logf("re-enabled local account %q", username)
	}
	return secret, nil
}

// Disable implements Manager.
func (n *NetAPI) Disable(username string) error {
	if !n.Ledger.Has(username) {
		return ErrNotManaged
	}
	flags, exists, err := getFlags(username)
	if err != nil || !exists {
		return err
	}
	if flags&ufAccountDisable != 0 {
		return nil
	}
	n.logf("disabling local account %q", username)
	return setFlags(username, flags|ufAccountDisable)
}

func getFlags(username string) (flags uint32, exists bool, err error) {
	name, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return 0, false, err
	}
	var buf *byte
	r, _, _ := procNetUserGetInfo.Call(0, uintptr(unsafe.Pointer(name)), 1, uintptr(unsafe.Pointer(&buf)))
	switch r {
	case nerrSuccess:
		defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(buf)))
		info := (*userInfo1)(unsafe.Pointer(buf))
		return info.Flags, true, nil
	case nerrUserNotFound:
		return 0, false, nil
	default:
		return 0, false, netErr("NetUserGetInfo", r)
	}
}

func userAdd(username, password, displayName string) error {
	name, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return err
	}
	pw, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return err
	}
	comment, _ := syscall.UTF16PtrFromString(Comment)
	info := userInfo1{
		Name:     name,
		Password: pw,
		Priv:     userPrivUser,
		Comment:  comment,
		Flags:    ufScript | ufDontExpirePasswd | ufNormalAccount,
	}
	var parmErr uint32
	r, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parmErr)))
	if r != nerrSuccess {
		return netErr("NetUserAdd", r)
	}
	if err := hideFromPicker(username); err != nil {
		// The account works without this; it is only cosmetic, so log and go on.
		log.Printf("hide %q from logon picker: %v", username, err)
	}
	return nil
}

// hideFromPicker keeps the derived local account off the Windows sign-in
// tile list. The only way in is the Rostor tile; a visible local tile would
// invite people to type their Rostor password into Windows' own provider,
// which can never succeed (the local secret is random and rotated).
func hideFromPicker(username string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(username, 0)
}

func setPassword(username, password string) error {
	name, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return err
	}
	pw, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return err
	}
	info := userInfo1003{Password: pw}
	var parmErr uint32
	r, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(name)), 1003, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parmErr)))
	if r != nerrSuccess {
		return netErr("NetUserSetInfo(1003)", r)
	}
	return nil
}

func setFlags(username string, flags uint32) error {
	name, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return err
	}
	info := userInfo1008{Flags: flags}
	var parmErr uint32
	r, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(name)), 1008, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parmErr)))
	if r != nerrSuccess {
		return netErr("NetUserSetInfo(1008)", r)
	}
	return nil
}

func setFullName(username, fullName string) error {
	if fullName == "" {
		return nil
	}
	name, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return err
	}
	fn, err := syscall.UTF16PtrFromString(fullName)
	if err != nil {
		return err
	}
	info := userInfo1011{FullName: fn}
	var parmErr uint32
	r, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(name)), 1011, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parmErr)))
	if r != nerrSuccess {
		return netErr("NetUserSetInfo(1011)", r)
	}
	return nil
}

// addToUsersGroup resolves BUILTIN\Users by well-known SID rather than by
// name, since the group's display name is localized.
func addToUsersGroup(username string) error {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return fmt.Errorf("users group sid: %w", err)
	}
	groupName, _, _, err := sid.LookupAccount("")
	if err != nil {
		return fmt.Errorf("users group name: %w", err)
	}
	group, err := syscall.UTF16PtrFromString(groupName)
	if err != nil {
		return err
	}
	member, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return err
	}
	info := localgroupMembersInfo3{DomainAndName: member}
	r, _, _ := procNetLocalGroupAddMembers.Call(0, uintptr(unsafe.Pointer(group)), 3, uintptr(unsafe.Pointer(&info)), 1)
	if r != nerrSuccess && r != errorMemberInAlias {
		return netErr("NetLocalGroupAddMembers", r)
	}
	return nil
}

func netErr(call string, status uintptr) error {
	return fmt.Errorf("%s: %w", call, windows.Errno(status))
}

func (n *NetAPI) logf(format string, args ...any) {
	if n.Logger != nil {
		n.Logger.Printf(format, args...)
	}
}
