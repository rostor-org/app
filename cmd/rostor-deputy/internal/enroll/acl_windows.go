//go:build windows

package enroll

import "golang.org/x/sys/windows"

// SecureKeyFile applies the contract §4 ACL to device.key: SYSTEM full
// control, Administrators read, nothing inherited.
func SecureKeyFile(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FR;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}
