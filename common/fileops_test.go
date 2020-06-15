package common

import "testing"

func TestOpenFile(t *testing.T) {
	broLogFn := "/usr/local/zeek/logs/current/dns.log"
	parseZeekLogHeader(broLogFn)
}

func TestZeekLogLineToSeparator(t *testing.T) {
	inputWithHex := "#separator \\x09"
	sep := zeekLogLineToSeparator(inputWithHex)
	shouldBe := "	"
	if sep != shouldBe {
		t.Errorf("seperator should have been '%s' but was '%s'", shouldBe, sep)
	}

	inputComma := "#separator ,"
	sep = zeekLogLineToSeparator(inputComma)
	shouldBe = ","
	if sep != shouldBe {
		t.Errorf("seperator should have been '%s' but was '%s'", shouldBe, sep)
	}

	inputShouldntBeProcessed := "hello"
	sep = zeekLogLineToSeparator(inputShouldntBeProcessed)
	shouldBe = ""
	if sep != shouldBe {
		t.Errorf("seperator should not have been processed when input was '%s'", inputShouldntBeProcessed)
	}
}