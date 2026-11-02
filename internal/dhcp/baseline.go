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
	mu                 sync.RWMutex
	filePath           string
	baselines          map[string]*ConfigBaseline // Key: interface name
	checkpointInterval time.Duration
	lastCheckpoint     time.Time
	dirty              bool
}

// NewBaselineStore loads or initializes the baseline storage at the specified path.
func NewBaselineStore(filePath string) (*BaselineStore, error) {
	if filePath == "" {
		filePath = "config/baselines.json"
	}

	store := &BaselineStore{
		filePath:           filePath,
		baselines:          make(map[string]*ConfigBaseline),
		checkpointInterval: 10 * time.Minute,
		lastCheckpoint:     time.Now(),
		dirty:              false,
	}

	if err := store.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load baseline store from %s: %w", filePath, err)
	}

	return store, nil
}

// SetCheckpointInterval adjusts the checkpoint flush interval (primarily for testing).
func (s *BaselineStore) SetCheckpointInterval(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkpointInterval = d
}

// IsDirty reports whether there are unflushed in-memory baseline updates.
func (s *BaselineStore) IsDirty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dirty
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

	// Backward compatibility: default missing type to INITIAL_OBSERVED
	for _, b := range loaded {
		if b != nil && b.Type == "" {
			b.Type = BaselineInitialObserved
		}
	}

	s.baselines = loaded
	return nil
}

// Backup creates a copy of the existing baseline file at <filePath>.bak.
func (s *BaselineStore) Backup() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.backupLocked()
}

func (s *BaselineStore) backupLocked() error {
	if s.filePath == "" {
		return nil
	}
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read baseline for backup: %w", err)
	}

	bakPath := s.filePath + ".bak"
	if err := os.WriteFile(bakPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write baseline backup: %w", err)
	}
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
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to write temporary baseline file: %w", err)
	}

	if err := os.Rename(tmpPath, s.filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to commit baseline file: %w", err)
	}

	s.dirty = false
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

// EstablishInitial records an initial observed baseline if none exists for the interface.
// If a baseline already exists, it is preserved without modification.
func (s *BaselineStore) EstablishInitial(cfg *DHCPConfig) (*ConfigBaseline, error) {
	if cfg == nil || cfg.InterfaceName == "" {
		return nil, fmt.Errorf("cannot establish baseline for nil configuration or empty interface")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.baselines[cfg.InterfaceName]; ok && existing != nil {
		cp := *existing
		return &cp, nil
	}

	now := time.Now()
	b := &ConfigBaseline{
		Type:          BaselineInitialObserved,
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

	prevDirty := s.dirty
	prevLastCheckpoint := s.lastCheckpoint

	s.baselines[cfg.InterfaceName] = b
	if err := s.save(); err != nil {
		delete(s.baselines, cfg.InterfaceName)
		s.dirty = prevDirty
		s.lastCheckpoint = prevLastCheckpoint
		return nil, err
	}

	cp := *b
	return &cp, nil
}

// EstablishConfirmed explicitly updates or creates a baseline with user confirmation.
// A backup copy is created before overwriting an existing baseline file.
func (s *BaselineStore) EstablishConfirmed(cfg *DHCPConfig) (*ConfigBaseline, error) {
	if cfg == nil || cfg.InterfaceName == "" {
		return nil, fmt.Errorf("cannot establish baseline for nil configuration or empty interface")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// If a baseline file exists, a recovery backup MUST succeed before overwriting.
	// If the backup cannot be written, abort immediately to protect the existing reference.
	if err := s.backupLocked(); err != nil {
		return nil, fmt.Errorf("backup creation failed, aborting baseline update to protect existing reference: %w", err)
	}

	now := time.Now()
	b := &ConfigBaseline{
		Type:          BaselineUserConfirmed,
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

	prevBaseline, hadPrev := s.baselines[cfg.InterfaceName]
	prevDirty := s.dirty
	prevLastCheckpoint := s.lastCheckpoint

	s.baselines[cfg.InterfaceName] = b
	if err := s.save(); err != nil {
		if hadPrev {
			s.baselines[cfg.InterfaceName] = prevBaseline
		} else {
			delete(s.baselines, cfg.InterfaceName)
		}
		s.dirty = prevDirty
		s.lastCheckpoint = prevLastCheckpoint
		return nil, err
	}

	cp := *b
	return &cp, nil
}

// Establish deliberately records or refreshes the baseline for the given observed configuration.
// It maintains backward compatibility with legacy callers.
func (s *BaselineStore) Establish(cfg *DHCPConfig) (*ConfigBaseline, error) {
	if cfg == nil || cfg.InterfaceName == "" {
		return nil, fmt.Errorf("cannot establish baseline for nil configuration or empty interface")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	bType := BaselineInitialObserved
	if existing, ok := s.baselines[cfg.InterfaceName]; ok && existing != nil && existing.Type == BaselineUserConfirmed {
		bType = BaselineUserConfirmed
	}

	b := &ConfigBaseline{
		Type:          bType,
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

	prevBaseline, hadPrev := s.baselines[cfg.InterfaceName]
	prevDirty := s.dirty
	prevLastCheckpoint := s.lastCheckpoint

	s.baselines[cfg.InterfaceName] = b
	if err := s.save(); err != nil {
		if hadPrev {
			s.baselines[cfg.InterfaceName] = prevBaseline
		} else {
			delete(s.baselines, cfg.InterfaceName)
		}
		s.dirty = prevDirty
		s.lastCheckpoint = prevLastCheckpoint
		return nil, err
	}

	cp := *b
	return &cp, nil
}

// TouchLastSeen updates the LastSeenAt timestamp in memory without rewriting disk on every cycle.
// Changes are committed to disk only when checkpoint interval elapses or on explicit Flush().
func (s *BaselineStore) TouchLastSeen(ifaceName string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.baselines[ifaceName]
	if !ok {
		return nil
	}
	prevLastSeen := b.LastSeenAt
	prevDirty := s.dirty
	prevLastCheckpoint := s.lastCheckpoint

	b.LastSeenAt = t
	s.dirty = true

	if time.Since(s.lastCheckpoint) >= s.checkpointInterval {
		s.lastCheckpoint = time.Now()
		if err := s.save(); err != nil {
			b.LastSeenAt = prevLastSeen
			s.dirty = prevDirty
			s.lastCheckpoint = prevLastCheckpoint
			return err
		}
	}
	return nil
}

// UpdateLastSeen delegates to TouchLastSeen to prevent continuous disk churn.
func (s *BaselineStore) UpdateLastSeen(ifaceName string, t time.Time) error {
	return s.TouchLastSeen(ifaceName, t)
}

// Flush writes any pending in-memory baseline state to disk immediately.
func (s *BaselineStore) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.dirty {
		return nil
	}
	prevLastCheckpoint := s.lastCheckpoint
	s.lastCheckpoint = time.Now()
	if err := s.save(); err != nil {
		s.lastCheckpoint = prevLastCheckpoint
		return err
	}
	return nil
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
