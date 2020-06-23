/*
Deals with dns.log parsing specifically.  Takes constructs created in logparse.go
and generates type cast structures specifically for dns.log parsing.
*/

package zeekparse

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// dns.log fields
// ------------
// defined here: https://docs.zeek.org/en/current/scripts/base/protocols/dns/main.zeek.html#type-DNS::Info
// description of common DNS fields: https://www.zytrax.com/books/dns/ch15/
// ------------
// TS:time - timestamp
// Uid:string - unique id
// id_orig_h:addr - senders address
// id_orig_p:addr - senders port
// id_resp_h:port - responders address
// id_resp_p:port - responders port
// Proto:enum - protocol
// trans_id:count - identifier assigned by the program that generated the Query.
// RTT:int - round trip time for Query + resp
// Query:string  - the Query
// QClass:count - QCLASS field in the question section
// qclass_name:string - descriptive name of the QCLASS
// QType:count - type of record being requested (value)
// qtype_name:string - rtype of record being requested (descriptive string)
// RCode:count - response being returned (value)
// rcode_name:string - response being returned (descriptive string)
// AA:bool - authorative response (set by responder)?
// TC:bool - truncated response (set by responder?
// RD:bool - recursion desired (by sender)?
// RA:bool - recursion available (set by responder)
// Z:count - reserved field (usually 0)
// Answers:vector[string] - all Answers
// TTLs:vector[interval] - vector of TTL of the responses lifespan in cache
// Rejected:bool - Rejected by server?

// Proto is an enum of tcp protocol, either TCP or UDP
type Proto string

const (
	TCP Proto = "TCP"
	UDP Proto = "UDP"
)

// ZeekNilValue is how null values are expressed in zeek logs, default is "-"
const ZeekNilValue = "-"

// DNSEntry is a fully parsed dns.log line.
type DNSEntry struct {
	TS         time.Time
	Uid        string
	IdOrigH    string
	IdOrigP    int
	IdRespH    string
	IdRespP    int
	Proto      Proto
	TransId    int
	RTT        float64
	Query      string
	QClass     int
	QClassName string
	QType      int
	QTypeName  string
	RCode      int
	RCodeName  string
	AA         bool
	TC         bool
	RD         bool
	RA         bool
	Z          int
	Answers    []string
	TTLs       []float64
	Rejected   bool
}

// Print will just print the DNS Query and response to the screen and include the server client info.
func (thisEntry *DNSEntry) Print() {
	fmt.Printf("(%s) client {%s:%d} asks server {%s:%d}:\n",
		thisEntry.TS.String(), thisEntry.IdOrigH, thisEntry.IdOrigP, thisEntry.IdRespH, thisEntry.IdRespP)
	fmt.Printf("\t%s -> %s\n", thisEntry.Query, thisEntry.Answers)
}

// ShortPrint will just print the DNS Query and response as a one liner
func (thisEntry *DNSEntry) ShortPrint() {
	fmt.Printf("[%s] %s -> %s\n", thisEntry.TS, thisEntry.Query, thisEntry.Answers)
}

func unixStrToTime(givenUnixStr string) (resultTime time.Time, err error) {
	var splitUnixTime []string
	splitUnixTime = strings.Split(givenUnixStr, ".")
	if len(splitUnixTime) != 2 {
		err = errors.New("incorrect input unixtime value")
		return
	}

	var intSec, intNSec int64
	intSec, err = strconv.ParseInt(splitUnixTime[0], 10, 64)
	if err != nil {
		return
	}

	intNSec, err = strconv.ParseInt(splitUnixTime[1], 10, 64)
	if err != nil {
		return
	}
	resultTime = time.Unix(intSec, intNSec)
	return
}

func thisLogEntryToDNSStruct(givenZeekLogEntry ZeekLogEntry, givenHeader *LogFileOpts) (DNSEntry DNSEntry, err error) {

	if len(givenHeader.setSeparator) == 0 {
		err = errors.New("no set seperator in header can't parse")
		return
	}

	for _, thisField := range givenZeekLogEntry {
		switch thisField.fieldName {
		case "ts":
			DNSEntry.TS, err = unixStrToTime(thisField.value)
			if err != nil {
				return
			}
		case "uid":
			DNSEntry.Uid = thisField.value
		case "id.orig_h":
			DNSEntry.IdOrigH = thisField.value
		case "id.orig_p":
			var convErr error
			DNSEntry.IdOrigP, convErr = strconv.Atoi(thisField.value)
			if convErr != nil {
				err = convErr
				return
			}
		case "id.resp_h":
			DNSEntry.IdRespH = thisField.value
		case "id.resp_p":
			DNSEntry.IdRespP, err = strconv.Atoi(thisField.value)
			if err != nil {
				return
			}
		case "proto":
			if thisField.value == "udp" {
				DNSEntry.Proto = UDP
			} else if thisField.value == "tcp" {
				DNSEntry.Proto = TCP
			}
		case "trans_id":
			DNSEntry.TransId, err = strconv.Atoi(thisField.value)
			if err != nil {
				return
			}
		case "rtt":
			if thisField.value == ZeekNilValue {
				DNSEntry.RTT = -1
			} else {
				DNSEntry.RTT, err = strconv.ParseFloat(thisField.value, 64)
				if err != nil {
					return
				}
			}
		case "query":
			DNSEntry.Query = thisField.value
		case "qclass":
			if thisField.value == ZeekNilValue {
				DNSEntry.QClass = -1
			} else {
				DNSEntry.QClass, err = strconv.Atoi(thisField.value)
				if err != nil {
					return
				}
			}
		case "qclass_name":
			DNSEntry.QClassName = thisField.value
		case "qtype":
			if thisField.value == ZeekNilValue {
				DNSEntry.QType = -1
			} else {
				DNSEntry.QType, err = strconv.Atoi(thisField.value)
				if err != nil {
					return
				}
			}
		case "qtype_name":
			DNSEntry.QTypeName = thisField.value
		case "rcode":
			if thisField.value == ZeekNilValue {
				DNSEntry.RCode = -1
			} else {
				DNSEntry.RCode, err = strconv.Atoi(thisField.value)
				if err != nil {
					return
				}
			}
		case "rcode_name":
			DNSEntry.RCodeName = thisField.value
		case "AA":
			DNSEntry.AA = thisField.value == "T"
		case "TC":
			DNSEntry.TC = thisField.value == "T"
		case "RD":
			DNSEntry.RD = thisField.value == "T"
		case "RA":
			DNSEntry.RA = thisField.value == "T"
		case "rejected":
			DNSEntry.Rejected = thisField.value == "T"
		case "Z":
			if thisField.value == ZeekNilValue {
				DNSEntry.Z = -1
			} else {
				DNSEntry.Z, err = strconv.Atoi(thisField.value)
				if err != nil {
					return
				}
			}
		case "answers":
			if thisField.value == ZeekNilValue {
				DNSEntry.Answers = append(DNSEntry.Answers, "")
			} else {
				splitSlice := strings.Split(thisField.value, givenHeader.setSeparator)
				DNSEntry.Answers = splitSlice
			}
		case "TTLs":
			if thisField.value == ZeekNilValue {
				DNSEntry.TTLs = append(DNSEntry.TTLs, -1)
			} else {
				splitSlice := strings.Split(thisField.value, givenHeader.setSeparator)
				for _, thisEntry := range splitSlice {
					var thisFloat float64
					thisFloat, err = strconv.ParseFloat(thisEntry, 64)
					if err != nil {
						return
					}
					DNSEntry.TTLs = append(DNSEntry.TTLs, thisFloat)
				}
			}
		default:
			log.Infof("unimplemented field: %s", thisField.fieldName)
		}
	}
	return
}

func parseDNSLog(givenFilename string) (parsedResults []DNSEntry, err error) {
	allUnparsedEntries, header, initialParseErr := parseZeekLog(givenFilename)
	if initialParseErr != nil {
		err = initialParseErr
		return
	}
	for _, thisResult := range allUnparsedEntries {
		var dnsRes DNSEntry
		dnsRes, err = thisLogEntryToDNSStruct(thisResult, header)
		if err != nil {
			log.Error(err)
			return
		}
		parsedResults = append(parsedResults, dnsRes)
	}
	return
}

func ParseDnsRecurse(givenDirectory string) (allResults []DNSEntry, err error) {
	var filenames []string

	err = filepath.Walk(givenDirectory,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if strings.Contains(path, "dns.") {
				filenames = append(filenames, path)
			}
			return nil
		})

	for _, thisFile := range filenames {
		thisResult, parseErr := parseDNSLog(thisFile)
		if parseErr != nil {
			err = parseErr
			return
		}

		allResults = append(allResults, thisResult...)
	}

	if err != nil {
		return
	}

	return
}
