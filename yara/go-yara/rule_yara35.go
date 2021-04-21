// Copyright © 2015-2019 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// +build !yara3.3,!yara3.4

package yara

// #include <yara.h>
import "C"
import "unsafe"

// Data returns the blob of data associated with the match. Returns nil if
// YARA was configured for not storing the matching data by passing zero to
// SetMaxMatchData.
func (m *Match) Data() []byte {
	if m.cptr.data_length == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(m.cptr.data), C.int(m.cptr.data_length))
}

// Length returns the length of the match.
func (m *Match) Length() int64 {
	return int64(m.cptr.match_length)
}
