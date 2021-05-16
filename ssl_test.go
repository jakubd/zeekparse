package zeekparse

import (
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestThisLogEntryToSSLStruct(t *testing.T) {
	log.SetFormatter(&log.TextFormatter{ForceColors: true})
	log.SetLevel(log.InfoLevel)

	// compressed case
	compressedResults, header, compErr := parseZeekLog("test_input/simple_ssl.log.gz")
	for _, thisResult := range compressedResults {
		_, dnsErr := thisLogEntryToSSLStruct(thisResult, header)
		assert.NoError(t, dnsErr)
	}
	assert.NoError(t, compErr)
}

