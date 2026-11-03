// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

import "unsafe"

func uintptrOf(p *[120]byte) uintptr { return uintptr(unsafe.Pointer(p)) }
