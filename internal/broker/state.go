package broker

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type persistedState struct {
	Version int               `json:"version"`
	Leases  map[string]string `json:"leases"`
}

type stateStore struct {
	mu     sync.Mutex
	path   string
	leases map[string]string
}

func loadStateStore(path string) (*stateStore, error) {
	store := &stateStore{path: path, leases: make(map[string]string)}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Vault lease state file is unsafe")
	}
	content, err := os.ReadFile(path)
	if err != nil || len(content) == 0 || len(content) > 4<<20 {
		return nil, errors.New("Vault lease state file is invalid")
	}
	var state persistedState
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || state.Version != 1 || state.Leases == nil {
		return nil, errors.New("Vault lease state file is invalid")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("Vault lease state file is invalid")
	}
	for key, accessor := range state.Leases {
		decoded, decodeErr := hex.DecodeString(key)
		if decodeErr != nil || len(decoded) != 32 || !validOpaqueSecret(accessor, 4096) {
			return nil, errors.New("Vault lease state file is invalid")
		}
		store.leases[key] = accessor
	}
	return store, nil
}

func (store *stateStore) accessor(key string) string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.leases[key]
}

func (store *stateStore) set(key, accessor string) error {
	if !validOpaqueSecret(accessor, 4096) {
		return errors.New("Vault lease accessor is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	previous, existed := store.leases[key]
	store.leases[key] = accessor
	if err := store.persistLocked(); err != nil {
		if existed {
			store.leases[key] = previous
		} else {
			delete(store.leases, key)
		}
		return err
	}
	return nil
}

func (store *stateStore) remove(key string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	previous, existed := store.leases[key]
	if !existed {
		return nil
	}
	delete(store.leases, key)
	if err := store.persistLocked(); err != nil {
		store.leases[key] = previous
		return err
	}
	return nil
}

func (store *stateStore) count() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.leases)
}

func (store *stateStore) persistLocked() error {
	directory := filepath.Dir(store.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("unable to prepare Vault lease state directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return errors.New("unable to protect Vault lease state directory")
	}
	content, err := json.Marshal(persistedState{Version: 1, Leases: store.leases})
	if err != nil {
		return errors.New("unable to encode Vault lease state")
	}
	handle, err := os.CreateTemp(directory, ".leases-*.tmp")
	if err != nil {
		return errors.New("unable to create Vault lease state")
	}
	temporary := handle.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temporary)
		}
	}()
	if err := handle.Chmod(0o600); err != nil {
		_ = handle.Close()
		return errors.New("unable to protect Vault lease state")
	}
	if _, err := handle.Write(content); err != nil {
		_ = handle.Close()
		return errors.New("unable to write Vault lease state")
	}
	if err := handle.Sync(); err != nil {
		_ = handle.Close()
		return errors.New("unable to synchronize Vault lease state")
	}
	if err := handle.Close(); err != nil {
		return errors.New("unable to close Vault lease state")
	}
	if err := os.Rename(temporary, store.path); err != nil {
		return errors.New("unable to activate Vault lease state")
	}
	cleanup = false
	return nil
}
