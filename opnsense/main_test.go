// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"os"
	"testing"
	"time"

	"github.com/pipiobjo/opnsense-api-go/internal/transport"
)

// TestMain shortens the waits between read retries: several tests talk to
// a closed port on purpose, and 30 seconds of retries per case would only
// slow them down. Retry behaviour itself is tested in internal/transport.
func TestMain(m *testing.M) {
	transport.RetryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	os.Exit(m.Run())
}
