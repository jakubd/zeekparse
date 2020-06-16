package zeekparse

import (
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseZeekLog(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	// uncompressed case
	err := parseZeekLog("test_input/simple_dns.log")
	assert.NoError(t, err)

	// compressed case
	err = parseZeekLog("test_input/simple_dns.log.gz")
	assert.NoError(t, err)
}
