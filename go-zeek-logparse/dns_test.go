package zeekparse

import (
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"net"
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

func BasicTestZeekParse(t *testing.T, givenEntry DNSEntry) {
	assert.True(t, len(givenEntry.uid) >= 15 && len(givenEntry.uid) <= 18)
	assert.True(t, net.ParseIP(givenEntry.idOrigH) != nil && net.ParseIP(givenEntry.idRespH) != nil)
	assert.True(t, givenEntry.idOrigP > 1 && givenEntry.idOrigP < 65539)
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
	_, err := parseDNSLog("test_input/simple_dns.log.gz")
	assert.NoError(t, err)
}

//
//// just a quick demo of parsing dns for some use
//// not actually "testing" anything
//func TestLocal(t *testing.T) {
//	allRes, err := parseDNSLog("/usr/local/zeek/logs/2019-11-04/dns.00:00:00-01:00:00.log.gz")
//	assert.NoError(t, err)
//	for _, thisResult := range allRes {
//		BasicTestZeekParse(t, thisResult)
//		if len(thisResult.answers) > 0 {
//			for _, thisAnswer := range thisResult.answers {
//				if len(thisAnswer) > 0 {
//					if thisResult.idRespH == "192.168.1.1" && !(strings.Contains(thisResult.query, "in-addr.arpa")) {
//						fmt.Println()
//						thisResult.Print()
//						fmt.Println()
//					} else {
//						//thisResult.ShortPrint()
//					}
//				}
//			}
//		}
//	}
//}
//
//func TestLocal2(t *testing.T) {
//	allRes, err := parseDnsRecurse("/usr/local/zeek/logs/2020-06-18/")
//	assert.NoError(t, err)
//	for _, thisResult := range allRes {
//		BasicTestZeekParse(t, thisResult)
//		if len(thisResult.answers) > 0 {
//			for _, thisAnswer := range thisResult.answers {
//				if len(thisAnswer) > 0 {
//					if thisResult.idRespH == "192.168.1.1" && !(strings.Contains(thisResult.query, "in-addr.arpa")) {
//						fmt.Println()
//						thisResult.Print()
//						fmt.Println()
//					} else {
//						//thisResult.ShortPrint()
//					}
//				}
//			}
//		}
//	}
//}
