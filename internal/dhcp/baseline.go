package dhcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// BaselineStore manages persistent network configuration baselines.
type BaselineStore struct {
	mu        sync.RWMutex
	filePath  string
	baselines map[string]*ConfigBaseline // Key: interface name
}

// NewBaselineStore loads or initializes the baseline storage at the specified path.
func NewBaselineStore(filePath string) (*BaselineStore, error) {
	if filePath == "" {
		filePath = "config/baselines.json"
	}

	store := &BaselineStore{
		filePath:  filePath,
		baselines: make(map[string]*ConfigBaseline),
	}

	if err := store.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load baseline store from %s: %w", filePath, err)
	}

	return store, nil
}

func (s *BaselineStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	var loaded map[string]*ConfigBaseline
	if err := json.Unmarshal(data, &loaded); err != nil {
		return fmt.Errorf("failed to decode baseline JSON: %w", err)
	}

	s.baselines = loaded
	return nil
}

func (s *BaselineStore) save() error {
	dir := filepath.Dir(s.filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create baseline directory %s: %w", dir, err)
		}
	}

	data, err := json.MarshalIndent(s.baselines, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode baselines: %w", err)
	}

	// Safe atomic write for USB flash drive resilience
	tmpPath := s.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temporary baseline file: %w", err)
	}

	if err := os.Rename(tmpPath, s.filePath); err != nil {
		return fmt.Errorf("failed to commit baseline file: %w", err)
	}

	return nil
}

// Get returns the baseline for the specified interface, if present.
func (s *BaselineStore) Get(ifaceName string) (*ConfigBaseline, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	b, ok := s.baselines[ifaceName]
	if !ok || b == nil {
		return nil, false
	}
	// Return a copy
	cp := *b
	return &cp, true
}

// Establish deliberately records or refreshes the baseline for the given observed configuration.
// It does not overwrite unless explicitly requested by the caller.
func (s *BaselineStore) Establish(cfg *DHCPConfig) (*ConfigBaseline, error) {
	if cfg == nil || cfg.InterfaceName == "" {
		return nil, fmt.Errorf("cannot establish baseline for nil configuration or empty interface")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	b := &ConfigBaseline{
		InterfaceName: cfg.InterfaceName,
		MACAddress:    cfg.MACAddress,
		IPv4Address:   cfg.IPv4Address,
		IPv4Prefix:    cfg.IPv4Prefix,
		Assignment:    cfg.Assignment,
		GatewayIP:     cfg.GatewayIP,
		DNSServers:    cfg.DNSServers,
		DHCPServerIP:  cfg.DHCPServerIP,
		DomainName:    cfg.DomainName,
		EstablishedAt: now,
		LastSeenAt:    now,
	}

	s.baselines[cfg.InterfaceName] = b
	if err := s.save(); err != nil {
		return nil, err
	}

	cp := *b
	return &cp, nil
}

// UpdateLastSeen updates the LastSeenAt timestamp for an existing baseline without modifying its baseline values.
func (s *BaselineStore) UpdateLastSeen(ifaceName string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.baselines[ifaceName]
	if !ok {
		return nil
	}
	b.LastSeenAt = t
	return s.save()
}

// List returns all recorded baselines.
func (s *BaselineStore) List() []*ConfigBaseline {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*ConfigBaseline
	for _, b := range s.baselines {
		cp := *b
		result = append(result, &cp)
	}
	return result
}
