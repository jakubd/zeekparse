package zeekparse

import (
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseZeekLog(t *testing.T) {
	log.SetLevel(log.InfoLevel)

	const numEntriesInLog = 3
	const fieldsInLog = 24

	// uncompressed case
	uncompressedResults, uncompErr := parseZeekLog("test_input/simple_dns.log")
	for _, thisResult := range uncompressedResults {
		assert.Equal(t, len(thisResult), fieldsInLog)
	}
	assert.True(t, len(uncompressedResults) == numEntriesInLog)
	assert.NoError(t, uncompErr)

	// compressed case
	compressedResults, compErr := parseZeekLog("test_input/simple_dns.log.gz")
	for _, thisResult := range compressedResults {
		assert.Equal(t, len(thisResult), fieldsInLog)
	}
	assert.True(t, len(compressedResults) == numEntriesInLog)
	assert.NoError(t, compErr)
}
