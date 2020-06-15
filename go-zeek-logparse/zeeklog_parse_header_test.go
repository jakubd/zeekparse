package go_zeek_logparse

import (
	"testing"
)

func assertStringsEqual(t *testing.T, value, shouldbe string) {
	if value != shouldbe {
		t.Errorf("value should be %s not %s", shouldbe, value)
	}
}

func assertNoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("error assert failed error thrown was: %s", err)
	}
}

func asserErrorThrown(t *testing.T, err error, errMsgShouldBe string) {
	if err.Error() != errMsgShouldBe {
		t.Errorf("error mismatch this should be thrown: '%s' but this is: '%s'", errMsgShouldBe, err)
	}
}

func zeekHeaderGoodCase(t *testing.T) {
	zeekLogFn := "test_input/proper_header.log"
	data, err := parseZeekLogHeader(zeekLogFn)
	assertNoError(t, err)

	if data.open.Year() == 0001 {
		t.Errorf("date wasnt parsed out of open")
	}

	assertStringsEqual(t, data.setSeparator, ",")
	assertStringsEqual(t, data.path, "dns")
	assertStringsEqual(t, data.emptyField, "(empty)")
	assertStringsEqual(t, data.unsetField, "-")

	if len(data.fieldMapping) == 0 {
		t.Errorf("fieldMapping was blank when parsing zeek log header")
	}
}

func zeekHeaderFileDoesntExist(t *testing.T) {
	broLogFn := "dndsfs.log"
	_, err := parseZeekLogHeader(broLogFn)
	asserErrorThrown(t, err, "open file error")
}

func zeekHeaderFieldsMismatched(t *testing.T) {
	broLogFn :=  "test_input/mismatched_fields_header.log"
	_, err := parseZeekLogHeader(broLogFn)
	asserErrorThrown(t, err, "mismatched header fields")
}

func zeekHeaderDateFieldParseFail(t *testing.T) {
	broLogFn :=  "test_input/bad_dates_header.log"
	_, err := parseZeekLogHeader(broLogFn)
	asserErrorThrown(t, err, "date not parsed for open field")
}

func TestParseZeekLogHeader(t *testing.T) {

	// test a correct formatted header
	zeekHeaderGoodCase(t)

	// test case where file doesn't exist
	zeekHeaderFileDoesntExist(t)

	// test case where header fields are mismatched
	zeekHeaderFieldsMismatched(t)

	// test case where date field is incorrect
	zeekHeaderDateFieldParseFail(t)
}

func TestUnescapeFieldValue(t *testing.T) {
	input := "something easy"
	shouldBe := "something easy"

	result := UnescapeFieldValue(input)
	assertStringsEqual(t, result, shouldBe)

	encodedInput := "\x09"
	shouldBe =  "	"

	result = UnescapeFieldValue(encodedInput)
	assertStringsEqual(t, result, shouldBe)
}

func TestZeekLogLineToSeparator(t *testing.T) {
	inputWithHex := "#separator \\x09"
	sep := zeekLogLineToSeparator(inputWithHex)
	shouldBe := "	"
	assertStringsEqual(t, sep, shouldBe)

	inputComma := "#separator ,"
	sep = zeekLogLineToSeparator(inputComma)
	shouldBe = ","
	assertStringsEqual(t, sep, shouldBe)

	inputShouldntBeProcessed := "hello"
	sep = zeekLogLineToSeparator(inputShouldntBeProcessed)
	shouldBe = ""
	assertStringsEqual(t, sep, shouldBe)
}

func TestZeekLogPullVar(t *testing.T) {
	input := "#dummyField value"
	fieldShouldBe := "dummyField"
	valueShouldBe := "value"

	field, value := zeekLogPullVar(input, " ")
	assertStringsEqual(t, field, fieldShouldBe)
	assertStringsEqual(t, value, valueShouldBe)

	input = "dummyField value"
	allShouldBe := ""

	field, value = zeekLogPullVar(input, " ")

	assertStringsEqual(t, field, allShouldBe)
	assertStringsEqual(t, value, allShouldBe)
}