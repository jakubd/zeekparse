package common

import (
	"testing"
)

func TestParseZeekLogHeader(t *testing.T) {
	broLogFn := "/usr/local/zeek/logs/current/dns.log"
	data, err := parseZeekLogHeader(broLogFn)

	if err != nil {
		t.Errorf("error opening a regular log file!")
	}

	setSetShouldBe := ","

	if data.setSeparator != setSetShouldBe {
		t.Errorf("set seperator not parsed from log header, should be %s not %s", setSetShouldBe, data.setSeparator)
	}

	pathShouldBe := "dns"

	if data.path != pathShouldBe {
		t.Errorf("path not parsed from log header, should be %s not %s", pathShouldBe, data.path)
	}

	emptySepShouldBe := "(empty)"

	if data.emptyField != emptySepShouldBe {
		t.Errorf("emptyField not parsing from log header should be %s not %s", emptySepShouldBe, data.emptyField)
	}

	unsetShouldBe := "-"

	if data.unsetField != unsetShouldBe {
		t.Errorf("unset not parsing from log header should be %s not %s", unsetShouldBe, data.unsetField)
	}

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

	if result != shouldBe {
		t.Errorf("unescape err should be %s but was %s", shouldBe, result)
	}

	encodedInput := "\x09"
	shouldBe =  "	"

	result = UnescapeFieldValue(encodedInput)
	if result != shouldBe {
		t.Errorf("unescape err should be %s but was %s", shouldBe, result)
	}
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

func TestZeekLogPullVar(t *testing.T) {
	input := "#dummyField value"
	fieldShouldBe := "dummyField"
	valueShouldBe := "value"

	field, value := zeekLogPullVar(input, " ")

	if field != fieldShouldBe {
		t.Errorf("field should be %s but was %s", fieldShouldBe, field)
	}

	if value != valueShouldBe {
		t.Errorf("value should be %s but was %s", valueShouldBe, value)
	}

	input = "dummyField value"
	allShouldBe := ""

	field, value = zeekLogPullVar(input, " ")

	if field != allShouldBe {
		t.Errorf("field should be %s but is %s", allShouldBe, field)
	}

	if value != allShouldBe {
		t.Errorf("value should be %s but is %s", allShouldBe, value)
	}
}