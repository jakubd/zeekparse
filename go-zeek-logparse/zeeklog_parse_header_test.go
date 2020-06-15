package zeekparse

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func zeekHeaderGoodCase(t *testing.T) {
	zeekLogFn := "test_input/proper_header.log"
	data, err := parseZeekLogHeader(zeekLogFn)

	assert.NoError(t, err)
	assert.NotEqual(t, data.open.Year(), 0001)

	assert.Equal(t, data.open.Year(), 2020)
	assert.Equal(t, data.setSeparator, ",")
	assert.Equal(t, data.path, "dns")
	assert.Equal(t, data.emptyField, "(empty)")
	assert.Equal(t, data.unsetField, "-")
	assert.True(t, len(data.fieldMapping) > 0)
}

func zeekHeaderFileDoesntExist(t *testing.T) {
	broLogFn := "dndsfs.log"
	_, err := parseZeekLogHeader(broLogFn)
	assert.Error(t, err, "open file error")
}

func zeekHeaderFieldsMismatched(t *testing.T) {
	broLogFn := "test_input/mismatched_fields_header.log"
	_, err := parseZeekLogHeader(broLogFn)
	assert.EqualError(t, err, "mismatched header fields")
}

func zeekHeaderDateFieldParseFail(t *testing.T) {
	broLogFn := "test_input/bad_dates_header.log"
	_, err := parseZeekLogHeader(broLogFn)
	assert.EqualError(t, err, "date not parsed for open field")
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

	result := unescapeFieldValue(input)
	assert.Equal(t, result, shouldBe)

	encodedInput := "\x09"
	shouldBe = "	"

	result = unescapeFieldValue(encodedInput)
	assert.Equal(t, result, shouldBe)
}

func TestZeekLogLineToSeparator(t *testing.T) {
	inputWithHex := "#separator \\x09"
	sep := zeekLogLineToSeparator(inputWithHex)
	assert.Equal(t, sep, "	")

	inputComma := "#separator ,"
	sep = zeekLogLineToSeparator(inputComma)
	assert.Equal(t, sep, ",")

	inputShouldntBeProcessed := "hello"
	sep = zeekLogLineToSeparator(inputShouldntBeProcessed)
	assert.Equal(t, sep, "")
}

func TestZeekLogPullVar(t *testing.T) {
	input := "#dummyField value"
	fieldShouldBe := "dummyField"
	valueShouldBe := "value"

	field, value := zeekLogPullVar(input, " ")
	assert.Equal(t, field, fieldShouldBe)
	assert.Equal(t, value, valueShouldBe)

	input = "dummyField value"
	allShouldBe := ""

	field, value = zeekLogPullVar(input, " ")
	assert.Equal(t, field, allShouldBe)
	assert.Equal(t, value, allShouldBe)
}
