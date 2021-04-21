package yara

import (
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"testing"
)

func makeScanner(t *testing.T, rule string) *Scanner {
	c, err := NewCompiler()
	if c == nil || err != nil {
		t.Fatal("NewCompiler():", err)
	}
	if err = c.AddString(rule, ""); err != nil {
		t.Fatal("AddString():", err)
	}
	r, err := c.GetRules()
	if err != nil {
		t.Fatal("GetRules:", err)
	}
	s, err := NewScanner(r)
	if err != nil {
		t.Fatal("NewScanner:", err)
	}
	return s
}

func TestScannerSimpleMatch(t *testing.T) {
	s := makeScanner(t,
		"rule test : tag1 { meta: author = \"Matt Blewitt\" strings: $a = \"abc\" fullword condition: $a }")
	m := MatchRules{}
	if err := s.SetCallback(&m).ScanMem([]byte(" abc ")); err != nil {
		t.Errorf("ScanMem: %s", err)
	} else if len(m) != 1 {
		t.Errorf("ScanMem: wanted 1 match, got %d", len(m))
	}
	t.Logf("Matches: %+v", m)
}

func TestScannerSimpleMatch2(t *testing.T) {
	s := makeScanner(t,
		"rule test : tag1 { meta: author = \"Matt Blewitt\" strings: $a = \"abc\" fullword condition: $a }")
	if m, err := s.ScanMem2([]byte(" abc ")); err != nil {
		t.Errorf("ScanMem: %s", err)
	} else if len(m) != 1 {
		t.Errorf("ScanMem: wanted 1 match, got %d", len(m))
	}
	if m, err := s.ScanMem2([]byte(" def ")); err != nil {
		t.Errorf("ScanMem: %s", err)
	} else if len(m) != 0 {
		t.Errorf("ScanMem: wanted 0 match, got %d", len(m))
	}
}

func TestScannerSimpleFileMatch(t *testing.T) {
	s := makeScanner(t,
		"rule test : tag1 { meta: author = \"Matt Blewitt\" strings: $a = \"abc\" fullword condition: $a }")
	tf, _ := ioutil.TempFile("", "TestScannerSimpleFileMatch")
	defer os.Remove(tf.Name())
	tf.Write([]byte(" abc "))
	tf.Close()
	var m MatchRules
	if err := s.SetCallback(&m).ScanFile(tf.Name()); err != nil {
		t.Errorf("ScanFile(%s): %s", tf.Name(), err)
	} else if len(m) != 1 {
		t.Errorf("ScanMem: wanted 1 match, got %d", len(m))
	}
	t.Logf("Matches: %+v", m)
}

func TestScannerSimpleFileDescriptorMatch(t *testing.T) {
	s := makeScanner(t,
		"rule test : tag1 { meta: author = \"Matt Blewitt\" strings: $a = \"abc\" fullword condition: $a }")
	tf, _ := ioutil.TempFile("", "TestScannerSimpleFileDescriptorMatch")
	defer os.Remove(tf.Name())
	tf.Write([]byte(" abc "))
	tf.Seek(0, os.SEEK_SET)
	var m MatchRules
	if err := s.SetCallback(&m).ScanFileDescriptor(tf.Fd()); err != nil {
		t.Errorf("ScanFileDescriptor(%v): %s", tf.Fd(), err)
	} else if len(m) != 1 {
		t.Errorf("ScanMem: wanted 1 match, got %d", len(m))
	}
	t.Logf("Matches: %+v", m)

}

// TestScannerIndependence tests that two scanners can
// execute with different external variables and the same ruleset
func TestScannerIndependence(t *testing.T) {
	rulesStr := `
		rule test {
			condition: bool_var and int_var == 1 and str_var == "foo"
		}
	`

	c, err := NewCompiler()
	if c == nil || err != nil {
		t.Fatal("NewCompiler():", err)
	}

	c.DefineVariable("bool_var", false)
	c.DefineVariable("int_var", 0)
	c.DefineVariable("str_var", "")

	if err = c.AddString(rulesStr, ""); err != nil {
		t.Fatal("AddString():", err)
	}

	r, err := c.GetRules()
	if err != nil {
		t.Fatal("GetRules:", err)
	}

	s1, err := NewScanner(r)
	if err != nil {
		t.Fatal("NewScanner:", err)
	}

	s2, err := NewScanner(r)
	if err != nil {
		t.Fatal("NewScanner:", err)
	}

	s1.DefineVariable("bool_var", true)
	s1.DefineVariable("int_var", 1)
	s1.DefineVariable("str_var", "foo")

	s2.DefineVariable("bool_var", false)
	s2.DefineVariable("int_var", 2)
	s2.DefineVariable("str_var", "bar")

	var m1, m2 MatchRules
	if err := s1.SetCallback(&m1).ScanMem([]byte("")); err != nil {
		t.Fatal(err)
	}

	if err := s2.SetCallback(&m2).ScanMem([]byte("")); err != nil {
		t.Fatal(err)
	}

	if !(len(m1) > 0) {
		t.Errorf("wanted >0 matches, got %d", len(m1))
	}

	if len(m2) != 0 {
		t.Errorf("wanted 0 matches, got %d", len(m2))
	}

	t.Logf("Matches 1: %+v", m1)
	t.Logf("Matches 2: %+v", m2)
}

func TestScannerImportDataCallback(t *testing.T) {
	cb := newTestCallback(t)
	s := makeScanner(t, `
		import "tests"
		import "pe"
		rule t1 { condition: true }
		rule t2 { condition: false }
		rule t3 {
			condition: tests.module_data == "callback-data-for-tests-module"
		}`)
	if err := s.SetCallback(cb).ScanMem([]byte("")); err != nil {
		t.Error(err)
	}
	for _, module := range []string{"tests", "pe"} {
		if _, ok := cb.modules[module]; !ok {
			t.Errorf("ImportModule was not called for %s", module)
		}
	}
	for _, rule := range []string{"t1", "t3"} {
		if _, ok := cb.matched["t1"]; !ok {
			t.Errorf("RuleMatching was not called for %s", rule)
		}
	}
	if _, ok := cb.notMatched["t2"]; !ok {
		t.Errorf("RuleNotMatching was not called for %s", "t2")
	}
	if !cb.finished {
		t.Errorf("ScanFinished was not called")
	}
	runtime.GC()
}

func TestScannerError(t *testing.T) {
	r := makeRules(t,
		`rule test {
			strings:
				$a = "aa"
			condition:
				$a
		 }`)

	s, err := NewScanner(r)
	if err != nil {
		t.Errorf("NewScanner: %s", err)
	}
	_, err = s.ScanMem2([]byte(strings.Repeat("a", 10000000)))
	if err == nil {
		t.Error("Expecting error")
	}

	if !strings.Contains(err.Error(), "test") {
		t.Error("Rule name expected in error message")
	}

	er := s.GetLastErrorRule()
	if er == nil {
		t.Error("The rule causing the error should not be nil")
	}
	if er.Identifier() != "test" {
		t.Error("The rule causing the error should be \"test\"")
	}

	es := s.GetLastErrorString()
	if es == nil {
		t.Error("The string causing the error should not be nil")
	}
	if es.Identifier() != "$a" {
		t.Error("The string causing the error should be \"$a\"")
	}
}
