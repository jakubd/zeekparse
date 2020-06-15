package common

import (
	"testing"
)

func shouldBeString(t *testing.T, value, shouldbe string) {
	if value != shouldbe {
		t.Errorf("value should be %s not %s", shouldbe, value)
	}
}

func TestParseZeekLogHeader(t *testing.T) {
	broLogFn := "/usr/local/zeek/logs/current/dns.log"
	data, err := parseZeekLogHeader(broLogFn)

	if err != nil {
		t.Errorf("error opening a regular log file!")
	}

	setSetShouldBe := ","
	shouldBeString(t, data.setSeparator, setSetShouldBe)

	pathShouldBe := "dns"
	shouldBeString(t, data.path, pathShouldBe)

	emptySepShouldBe := "(empty)"
	shouldBeString(t, data.emptyField, emptySepShouldBe)

	unsetShouldBe := "-"
	shouldBeString(t, data.unsetField, unsetShouldBe)

	// what if we try to parse a bad file
	broLogFn = "/usr/local/zeek/logs/current/dndsfs.log"
	_, err = parseZeekLogHeader(broLogFn)
	errShouldBe := "open file error"
	if err.Error() != errShouldBe {
		t.Errorf("error mismatch should %s but is %s", errShouldBe, err)
	}

}

func TestUnescapeFieldValue(t *testing.T) {
	input := "something easy"
	shouldBe := "something easy"

	result := UnescapeFieldValue(input)
	shouldBeString(t, result, shouldBe)

	encodedInput := "\x09"
	shouldBe =  "	"

	result = UnescapeFieldValue(encodedInput)
	shouldBeString(t, result, shouldBe)
}

func TestZeekLogLineToSeparator(t *testing.T) {
	inputWithHex := "#separator \\x09"
	sep := zeekLogLineToSeparator(inputWithHex)
	shouldBe := "	"
	shouldBeString(t, sep, shouldBe)

	inputComma := "#separator ,"
	sep = zeekLogLineToSeparator(inputComma)
	shouldBe = ","
	shouldBeString(t, sep, shouldBe)

	inputShouldntBeProcessed := "hello"
	sep = zeekLogLineToSeparator(inputShouldntBeProcessed)
	shouldBe = ""
	shouldBeString(t, sep, shouldBe)
}

func TestZeekLogPullVar(t *testing.T) {
	input := "#dummyField value"
	fieldShouldBe := "dummyField"
	valueShouldBe := "value"

	field, value := zeekLogPullVar(input, " ")
	shouldBeString(t, field, fieldShouldBe)
	shouldBeString(t, value, valueShouldBe)

	input = "dummyField value"
	allShouldBe := ""

	field, value = zeekLogPullVar(input, " ")

	shouldBeString(t, field, allShouldBe)
	shouldBeString(t, value, allShouldBe)
}