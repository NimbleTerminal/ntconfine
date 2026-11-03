// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package confine

import (
	"errors"
	"syscall"
)

func socketpairCloexec() ([2]int, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOSYS) {
		syscall.ForkLock.RLock()
		fds, err = syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err == nil {
			syscall.CloseOnExec(fds[0])
			syscall.CloseOnExec(fds[1])
		}
		syscall.ForkLock.RUnlock()
	}
	return fds, err
}
