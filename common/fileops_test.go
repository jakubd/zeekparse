package common

import "testing"

func TestOpenFile(t *testing.T) {
	broLogFn := "/usr/local/zeek/logs/current/dns.log"
	parseZeekLogHeader(broLogFn)

	// what if we try to parse a bad file
	broLogFn = "/usr/local/zeek/logs/current/dndsfs.log"
	_, err := parseZeekLogHeader(broLogFn)
	errShouldBe := "open file error"
	if err.Error() != errShouldBe {
		t.Errorf("error mismatch should %s but is %s", errShouldBe, err)
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