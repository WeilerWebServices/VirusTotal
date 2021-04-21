// Copyright © 2015-2019 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// +build !yara3.3,!yara3.4,!yara3.5,!yara3.6,!yara3.7

package yara

/*
#include <yara.h>
*/
import "C"
import "C"

import "unsafe"

// GetMaxMatchData returns the value for YARA's YR_CONFIG_MAX_MATCH_DATA
// configuration option. This controls the maximum amount of bytes that YARA
// stores for each matching string.
func GetMaxMatchData() int {
	var m C.uint32_t
	C.yr_get_configuration(C.YR_CONFIG_MAX_MATCH_DATA, unsafe.Pointer(&m))
	return int(m)
}

// SetMaxMatchData sets the value for YR_CONFIG_MAX_MATCH_DATA configuration
// option, which controls the maximum amount of bytes that YARA stores for each
// matching string. If this value is zero YARA won't copy any data at all.
func SetMaxMatchData(n int) {
	a := C.uint32_t(n)
	C.yr_set_configuration(C.YR_CONFIG_MAX_MATCH_DATA, unsafe.Pointer(&a))
}
