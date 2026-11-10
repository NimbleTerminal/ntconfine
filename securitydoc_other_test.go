// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

//go:build !darwin

package ntconfine

// renderMacOSProfile reports that the macOS profile region can only be
// rendered, checked, and updated on macOS.
func renderMacOSProfile() *string { return nil }
