package zeekparse

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDNSParse(t *testing.T) {
	log.SetFormatter(&log.TextFormatter{ForceColors: true})
	log.SetLevel(log.InfoLevel)

	// compressed case
	compressedResults, compErr := parseZeekLog("test_input/simple_dns.log.gz")
	for _, thisResult := range compressedResults {
		fmt.Println(thisResult)
		dnsRes, dnsErr := thisLogEntryToDNSStruct(thisResult)
		assert.NoError(t, dnsErr)
		fmt.Println(dnsRes)
		assert.True(t, len(dnsRes.uid) >= 17 && len(dnsRes.uid) <= 18)
	}
	assert.NoError(t, compErr)
}
