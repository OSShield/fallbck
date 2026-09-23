//go:build windows

package credstore

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The key file is wrapped with DPAPI (CRYPTPROTECT_LOCAL_MACHINE off, so the blob
// only opens under the account that wrote it: the agent's service account). A key
// written by another account, or copied to another machine, fails to unwrap.

var entropy = []byte("fallbck-agent credential store")

func wrapKey(key []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(key)), Data: &key[0]}
	ent := windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, windows.StringToUTF16Ptr("fallbck credential key"), &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func unwrapKey(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty key file")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	ent := windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, errors.New("DPAPI could not unwrap the key: it was written by another Windows account or on another machine (" + err.Error() + ")")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
