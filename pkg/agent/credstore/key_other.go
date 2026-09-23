//go:build !windows

package credstore

// The key file is protected by its 0600 mode alone outside Windows; the data
// directory itself is root-only on packaged installs
func wrapKey(key []byte) ([]byte, error)    { return key, nil }
func unwrapKey(data []byte) ([]byte, error) { return data, nil }
