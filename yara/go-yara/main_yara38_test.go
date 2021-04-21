// Copyright © 2015-2019 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// +build !yara3.3,!yara3.4,!yara3.5,!yara3.6,!yara3.7

package yara

import "testing"

func TestMaxMatchData(t *testing.T) {
	oldMax := GetMaxMatchData()
	SetMaxMatchData(0)
	r, err := Compile("rule t {strings: $a = \"abc\" condition: $a}", nil)
	if err != nil {
		t.Errorf("Compile: %s", err)
	}
	m, err := r.ScanMem([]byte("abc"), 0, 0)
	if err != nil {
		t.Errorf("ScanMem: %s", err)
	}
	if m[0].Strings[0].Data != nil {
		t.Errorf("expecting nil")
	}
	maxMatchData := 1
	SetMaxMatchData(maxMatchData)
	m, err = r.ScanMem([]byte("abc"), 0, 0)
	if err != nil {
		t.Errorf("ScanMem: %s", err)
	}
	if len(m[0].Strings[0].Data) != maxMatchData {
		t.Errorf("expecting %d, got %d", maxMatchData, len(m[0].Strings[0].Data))
	}
	SetMaxMatchData(oldMax)
}
