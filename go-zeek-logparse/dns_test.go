package zeekparse

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestUnixStrToTime(t *testing.T) {
	timestr := "1592266854.705260"
	result, err := unixStrToTime(timestr)
	assert.NoError(t, err)
	assert.Equal(t, result.Year(), 2020)
	assert.Equal(t, result.Month(), time.Month(6))
	assert.Equal(t, result.Minute(), 20)
	assert.Equal(t, result.Second(), 54)

	failTimeStr := "hello"
	result, err = unixStrToTime(failTimeStr)
	assert.Error(t, err)

	failTimeStr = "1592266854.hello"
	result, err = unixStrToTime(failTimeStr)
	assert.Error(t, err)

	failTimeStr = "hello.705260"
	result, err = unixStrToTime(failTimeStr)
	assert.Error(t, err)
}

func TestThisLogEntryToDNSStruct(t *testing.T) {
	log.SetFormatter(&log.TextFormatter{ForceColors: true})
	log.SetLevel(log.InfoLevel)

	// compressed case
	compressedResults, header, compErr := parseZeekLog("test_input/simple_dns.log.gz")
	for _, thisResult := range compressedResults {
		dnsRes, dnsErr := thisLogEntryToDNSStruct(thisResult, header)
		assert.NoError(t, dnsErr)
		assert.True(t, len(dnsRes.uid) >= 17 && len(dnsRes.uid) <= 18)
	}
	assert.NoError(t, compErr)
}

func TestParseDNSLog(t *testing.T) {
	allRes, err := parseDNSLog("test_input/simple_dns.log.gz")
	assert.NoError(t, err)
	fmt.Println(allRes)
}
