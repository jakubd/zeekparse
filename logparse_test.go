package go_zeek_logparse

import (
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"testing"
)

func basicCheckofParse(t *testing.T, results []ZeekLogEntry, entryCountExpected, fieldCountExpected int) {
	assert.True(t, len(results) == entryCountExpected)
	for _, thisResult := range results {
		assert.Equal(t, len(thisResult), fieldCountExpected)
	}
}

func TestParseZeekLog(t *testing.T) {
	log.SetLevel(log.InfoLevel)

	const numEntriesInLog = 3
	const fieldsInLog = 24

	// uncompressed case
	uncompressedResults, header, uncompErr := parseZeekLog("test_input/simple_dns.log")
	basicCheckofParse(t, uncompressedResults, numEntriesInLog, fieldsInLog)
	assert.True(t, len(header.setSeparator) > 0)
	assert.NoError(t, uncompErr)

	// compressed case
	compressedResults, _, compErr := parseZeekLog("test_input/simple_dns.log.gz")
	basicCheckofParse(t, compressedResults, numEntriesInLog, fieldsInLog)
	assert.NoError(t, compErr)
}
