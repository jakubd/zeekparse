package zeekparse

import (
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func BasicTestZeekParse(t *testing.T, givenEntry DnsEntry) {
	assert.True(t, len(givenEntry.Uid) >= 14 && len(givenEntry.Uid) <= 19)
	assert.True(t, net.ParseIP(givenEntry.IdOrigH) != nil && net.ParseIP(givenEntry.IdRespH) != nil)
	assert.True(t, givenEntry.IdOrigP > 1 && givenEntry.IdOrigP < 65539)
}

func TestThisLogEntryToDNSStruct(t *testing.T) {
	log.SetFormatter(&log.TextFormatter{ForceColors: true})
	log.SetLevel(log.InfoLevel)

	// compressed case
	compressedResults, header, compErr := parseZeekLog("test_input/simple_dns.log.gz")
	for _, thisResult := range compressedResults {
		dnsRes, dnsErr := thisLogEntryToDNSStruct(thisResult, header)
		assert.NoError(t, dnsErr)
		BasicTestZeekParse(t, dnsRes)
	}
	assert.NoError(t, compErr)
}

func TestParseDNSLog(t *testing.T) {
	_, err := ParseDNSLog("test_input/simple_dns.log.gz")
	assert.NoError(t, err)
}
