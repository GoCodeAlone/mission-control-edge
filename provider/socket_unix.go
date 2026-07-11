//go:build !windows

package provider

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// ListenUnix creates a provider socket only below an owner-private directory.
// Existing entries, symlinks, and group/world-accessible parents are refused.
func ListenUnix(path string) (net.Listener, error) {
	clean, err := validateUnixParent(path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(clean); err == nil {
		return nil, fmt.Errorf("provider: unix socket path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("provider: inspect unix socket path: %w", err)
	}

	listener, err := net.Listen("unix", clean)
	if err != nil {
		return nil, fmt.Errorf("provider: listen on unix socket: %w", err)
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		return nil, fmt.Errorf("provider: unix listener type is unavailable")
	}
	// net.UnixListener otherwise unlinks the pathname unconditionally during
	// Close. Disable that behavior so ownedUnixListener can compare the bound
	// inode before removing anything.
	unixListener.SetUnlinkOnClose(false)
	cleanup := true
	defer func() {
		if cleanup {
			_ = listener.Close()
			_ = os.Remove(clean)
		}
	}()
	if err := os.Chmod(clean, 0o600); err != nil {
		return nil, fmt.Errorf("provider: restrict unix socket: %w", err)
	}
	info, err := validateUnixSocket(clean)
	if err != nil {
		return nil, err
	}
	device, inode, err := unixIdentity(info)
	if err != nil {
		return nil, err
	}
	cleanup = false
	return &ownedUnixListener{Listener: listener, path: clean, device: device, inode: inode}, nil
}

// DialUnix connects only to an owner-private socket below an owner-private
// non-symlink directory.
func DialUnix(ctx context.Context, path string) (net.Conn, error) {
	clean, err := validateUnixParent(path)
	if err != nil {
		return nil, err
	}
	before, err := validateUnixSocket(clean)
	if err != nil {
		return nil, err
	}
	beforeDevice, beforeInode, err := unixIdentity(before)
	if err != nil {
		return nil, err
	}
	var dialer net.Dialer
	connection, err := dialer.DialContext(ctx, "unix", clean)
	if err != nil {
		return nil, fmt.Errorf("provider: dial unix socket: %w", err)
	}
	after, validateErr := validateUnixSocket(clean)
	if validateErr != nil {
		_ = connection.Close()
		return nil, validateErr
	}
	afterDevice, afterInode, identityErr := unixIdentity(after)
	if identityErr != nil || beforeDevice != afterDevice || beforeInode != afterInode {
		_ = connection.Close()
		if identityErr != nil {
			return nil, identityErr
		}
		return nil, fmt.Errorf("provider: unix socket changed during dial")
	}
	return connection, nil
}

type ownedUnixListener struct {
	net.Listener
	path   string
	device string
	inode  string
	once   sync.Once
	err    error
}

func (l *ownedUnixListener) Close() error {
	l.once.Do(func() {
		closeErr := l.Listener.Close()
		info, statErr := os.Lstat(l.path)
		switch {
		case errors.Is(statErr, os.ErrNotExist):
		case statErr != nil:
			l.err = fmt.Errorf("provider: inspect unix socket during close: %w", statErr)
		default:
			device, inode, identityErr := unixIdentity(info)
			if identityErr != nil {
				l.err = identityErr
			} else if info.Mode()&os.ModeSocket != 0 && device == l.device && inode == l.inode {
				if removeErr := os.Remove(l.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
					l.err = fmt.Errorf("provider: remove unix socket: %w", removeErr)
				}
			}
		}
		if l.err == nil && closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			l.err = closeErr
		}
	})
	return l.err
}

func validateUnixParent(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("provider: unix socket path must be absolute")
	}
	clean := filepath.Clean(path)
	if clean != path {
		return "", fmt.Errorf("provider: unix socket path must be clean")
	}
	parent := filepath.Dir(clean)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("provider: resolve unix socket parent: %w", err)
	}
	if resolved != parent {
		return "", fmt.Errorf("provider: unix socket parent must not traverse symlinks")
	}
	info, err := os.Lstat(parent)
	if err != nil {
		return "", fmt.Errorf("provider: inspect unix socket parent: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("provider: unix socket parent is not a directory")
	}
	if info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o300 != 0o300 {
		return "", fmt.Errorf("provider: unix socket parent permissions are unsafe")
	}
	if err := requireCurrentOwner(info); err != nil {
		return "", err
	}
	return clean, nil
}

func validateUnixSocket(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("provider: inspect unix socket: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("provider: unix socket path is not a socket")
	}
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("provider: unix socket permissions are unsafe")
	}
	if err := requireCurrentOwner(info); err != nil {
		return nil, err
	}
	return info, nil
}

func requireCurrentOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("provider: unix ownership information is unavailable")
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("provider: unix path is owned by another user")
	}
	return nil
}

func unixIdentity(info os.FileInfo) (string, string, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", "", fmt.Errorf("provider: unix identity information is unavailable")
	}
	return fmt.Sprintf("%d", stat.Dev), fmt.Sprintf("%d", stat.Ino), nil
}
