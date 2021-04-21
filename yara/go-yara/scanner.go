// Copyright © 2015-2019 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// +build !yara3.3,!yara3.4,!yara3.5,!yara3.6,!yara3.7

package yara

/*
#include <yara.h>
#ifdef _WIN32
#include <stdint.h>
int _yr_scanner_scan_fd(
    YR_SCANNER* scanner,
    int fd)
{
  return yr_scanner_scan_fd(scanner, (YR_FILE_DESCRIPTOR)(intptr_t)fd);
}
#else
#define _yr_scanner_scan_fd yr_scanner_scan_fd
#endif

YR_RULE_PROFILING_INFO* profiling_info(YR_RULE_PROFILING_INFO* p, int n)
{
  if (p[n].rule == NULL)
    return NULL;
  return &p[n];
}


int scanCallbackFunc(int, void*, void*);
*/
import "C"
import (
	"errors"
	"runtime"
	"time"
	"unsafe"
)

// ScanFlags are used to tweak the scanner's behaviour. They are also used
// with rule's ScanX functions.
type ScanFlags int

const (
	// ScanFlagsFastMode avoids multiple matches of the same string
	// when not necessary.
	ScanFlagsFastMode = C.SCAN_FLAGS_FAST_MODE
	// ScanFlagsProcessMemory causes the scanned data to be
	// interpreted like live, in-process memory rather than an on-disk
	// file.
	ScanFlagsProcessMemory = C.SCAN_FLAGS_PROCESS_MEMORY
	// Flags for indicating that the callback function should for matching and
	// not matching rules. Both flags can be used together for receiving
	// notification about matching and not matching rules, or they can be used
	// alone for receiving notifications about either case. If none of these
	// two flags are specified the default behaviour is reporting both matching
	// and not matching rules.
	ScanFlagsReportRulesMatching    = C.SCAN_FLAGS_REPORT_RULES_MATCHING
	ScanFlagsReportRulesNotMatching = C.SCAN_FLAGS_REPORT_RULES_NOT_MATCHING
)

// Scanner represents a YARA scanner.
type Scanner struct {
	*scanner
	// The Scanner struct has to hold a pointer to the rules
	// it wraps, as otherwise it may be be garbage collected.
	rules *Rules
	cb    unsafe.Pointer
}

type scanner struct {
	cptr *C.YR_SCANNER
}

func (s *Scanner) newScanError(code C.int) error {
	if code == C.ERROR_SUCCESS {
		return nil
	}
	err := Error{Code: int(code)}
	if rule := s.GetLastErrorRule(); rule != nil {
		err.RuleIdentifier = rule.Identifier()
		err.Namespace = rule.Namespace()
	}
	if str := s.GetLastErrorString(); str != nil {
		err.StringIdentifier = str.Identifier()
	}
	return err
}

// NewScanner creates a YARA scanner.
func NewScanner(r *Rules) (*Scanner, error) {
	var yrScanner *C.YR_SCANNER
	if err := newError(C.yr_scanner_create(r.cptr, &yrScanner)); err != nil {
		return nil, err
	}
	s := &Scanner{scanner: &scanner{cptr: yrScanner}, rules: r}
	runtime.SetFinalizer(s.scanner, (*scanner).finalize)
	return s, nil
}

func (s *scanner) finalize() {
	C.yr_scanner_destroy(s.cptr)
	runtime.SetFinalizer(s, nil)
}

// Destroy destroys the YARA data structure representing a scanner.
// Since a Finalizer for the underlying YR_SCANNER structure is
// automatically set up on creation, it should not be necessary to
// explicitly all this method.
func (s *Scanner) Destroy() {
	s.unsetCallback()
	if s.scanner != nil {
		s.scanner.finalize()
		s.scanner = nil
	}
}

// DefineVariable defines a named variable for use by the scanner.
// Boolean, int64, float64, and string types are supported.
func (s *Scanner) DefineVariable(identifier string, value interface{}) (err error) {
	cid := C.CString(identifier)
	defer C.free(unsafe.Pointer(cid))
	switch value.(type) {
	case bool:
		var v int
		if value.(bool) {
			v = 1
		}
		err = newError(C.yr_scanner_define_boolean_variable(
			s.cptr, cid, C.int(v)))
	case int, int8, int16, int32, int64, uint, uint8, uint32, uint64:
		value := toint64(value)
		err = newError(C.yr_scanner_define_integer_variable(
			s.cptr, cid, C.int64_t(value)))
	case float64:
		err = newError(C.yr_scanner_define_float_variable(
			s.cptr, cid, C.double(value.(float64))))
	case string:
		cvalue := C.CString(value.(string))
		defer C.free(unsafe.Pointer(cvalue))
		err = newError(C.yr_scanner_define_string_variable(
			s.cptr, cid, cvalue))
	default:
		err = errors.New("wrong value type passed to DefineVariable; bool, int64, float64, string are accepted")
	}
	keepAlive(s)
	return
}

// SetFlags sets flags for the scanner.
func (s *Scanner) SetFlags(flags ScanFlags) *Scanner {
	C.yr_scanner_set_flags(s.cptr, C.int(flags))
	return s
}

// SetTimeout sets a timeout for the scanner.
func (s *Scanner) SetTimeout(timeout time.Duration) *Scanner {
	C.yr_scanner_set_timeout(s.cptr, C.int(timeout/time.Second))
	return s
}

func (s *Scanner) unsetCallback() {
	if s.cb != nil {
		callbackData.Get(s.cb).(*scanCallbackContainer).destroy()
		callbackData.Delete(s.cb)
		s.cb = nil
	}
}

// SetCallback sets a callback object for the scanner. For every event
// emitted by libyara during subsequent scan, the appropriate method
// on the ScanCallback object is called.
//
// Setting a callback object is not necessary (and will be overridden)
// when using any of the ScanXXX2 methods.
func (s *Scanner) SetCallback(cb ScanCallback) *Scanner {
	s.unsetCallback()
	if cb == nil {
		return s
	}
	s.cb = callbackData.Put(&scanCallbackContainer{ScanCallback: cb})
	C.yr_scanner_set_callback(s.cptr, C.YR_CALLBACK_FUNC(C.scanCallbackFunc), s.cb)
	return s
}

// ScanMem scans an in-memory buffer using the scanner.
func (s *Scanner) ScanMem(buf []byte) (err error) {
	var ptr *C.uint8_t
	if len(buf) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&(buf[0])))
	}
	err = s.newScanError(C.yr_scanner_scan_mem(
		s.cptr,
		ptr,
		C.size_t(len(buf))))
	keepAlive(s)
	return
}

func (s *Scanner) ScanMem2(buf []byte) (matches []MatchRule, err error) {
	var m MatchRules
	if err = s.SetCallback(&m).ScanMem(buf); err == nil {
		matches = m
	}
	s.unsetCallback()
	return
}

// ScanFile scans a file using the scanner.
func (s *Scanner) ScanFile(filename string) (err error) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	err = s.newScanError(C.yr_scanner_scan_file(
		s.cptr,
		cfilename,
	))
	keepAlive(s)
	return
}

func (s *Scanner) ScanFile2(filename string) (matches []MatchRule, err error) {
	var m MatchRules
	if err = s.SetCallback(&m).ScanFile(filename); err == nil {
		matches = m
	}
	s.unsetCallback()
	return
}

// ScanFileDescriptor scans a file using the scanner.
func (s *Scanner) ScanFileDescriptor(fd uintptr) (err error) {
	err = s.newScanError(C.yr_scanner_scan_fd(
		s.cptr,
		C.int(fd),
	))
	keepAlive(s)
	return
}

func (s *Scanner) ScanFileDescriptor2(fd uintptr) (matches []MatchRule, err error) {
	var m MatchRules
	if err = s.SetCallback(&m).ScanFileDescriptor(fd); err == nil {
		matches = m
	}
	s.unsetCallback()
	return
}

// ScanProc scans a live process using the scanner.
func (s *Scanner) ScanProc(pid int) (err error) {
	err = s.newScanError(C.yr_scanner_scan_proc(
		s.cptr,
		C.int(pid),
	))
	keepAlive(s)
	return
}

func (s *Scanner) ScanProc2(pid int) (matches []MatchRule, err error) {
	var m MatchRules
	if err = s.SetCallback(&m).ScanProc(pid); err == nil {
		matches = m
	}
	s.unsetCallback()
	return
}

// GetLastErrorRule returns the rule that caused the last scanner error.
func (s *Scanner) GetLastErrorRule() *Rule {
	r := C.yr_scanner_last_error_rule(s.cptr)
	if r == nil {
		return nil
	}
	return &Rule{r}
}

// GetLastErrorString returns the string that caused the last scanner error.
func (s *Scanner) GetLastErrorString() *String {
	str := C.yr_scanner_last_error_string(s.cptr)
	if str == nil {
		return nil
	}
	return &String{str}
}

type ProfilingInfo struct {
	Rule *Rule
	Cost uint64
}

// GetProfilingInfo returns a list of ProfilingInfo structures containing the
// profiling information for the slowest n rules.
func (s *Scanner) GetProfilingInfo(n int) (result []ProfilingInfo) {
	pi := C.yr_scanner_get_profiling_info(s.cptr)
	if pi == nil {
		return
	}
	for i := 0; i < n; i++ {
		p := C.profiling_info(pi, C.int(i))
		if p == nil {
			break
		}
		result = append(result, ProfilingInfo{&Rule{cptr: p.rule}, uint64(p.cost)})
	}
	return
}

// ResetProfilingInfo resets the profiling information accumulated by the scanner
// so far. When you scan multiple files/buffer with the same scanner the profiling
// information is not automatically reset after each scan, instead it gets
// accumulated. If you want to reset profiling information so that the counters
// start a zero again you must call this function.
func (s *Scanner) ResetProfilingInfo() {
	C.yr_scanner_reset_profiling_info(s.cptr)
}
