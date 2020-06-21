/*
Deals with dns.log parsing specifically.  Takes constructs created in logparse.go
and generates type cast structures specifically for dns.log parsing.
*/

package zeekparse

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"strconv"
	"strings"
	"time"
)

// dns.log fields
// ------------
// defined here: https://docs.zeek.org/en/current/scripts/base/protocols/dns/main.zeek.html#type-DNS::Info
// description of common DNS fields: https://www.zytrax.com/books/dns/ch15/
// ------------
// ts:time - timestamp
// uid:string - unique id
// id_orig_h:addr - senders address
// id_orig_p:addr - senders port
// id_resp_h:port - responders address
// id_resp_p:port - responders port
// proto:enum - protocol
// trans_id:count - identifier assigned by the program that generated the query.
// rtt:int - round trip time for query + resp
// query:string  - the query
// qclass:count - QCLASS field in the question section
// qclass_name:string - descriptive name of the QCLASS
// qtype:count - type of record being requested (value)
// qtype_name:string - rtype of record being requested (descriptive string)
// rcode:count - response being returned (value)
// rcode_name:string - response being returned (descriptive string)
// AA:bool - authorative response (set by responder)?
// TC:bool - truncated response (set by responder?
// RD:bool - recursion desired (by sender)?
// RA:bool - recursion available (set by responder)
// Z:count - reserved field (usually 0)
// answers:vector[string] - all answers
// TTLs:vector[interval] - vector of TTL of the responses lifespan in cache
// rejected:bool - rejected by server?

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
	ts         time.Time
	uid        string
	idOrigH    string
	idOrigP    int
	idRespH    string
	idRespP    int
	proto      Proto
	transId    int
	rtt        int
	query      string
	qclass     int
	qclassName string
	qtype      int
	qtypeName  string
	rcode      int
	rcodeName  string
	AA         bool
	TC         bool
	RD         bool
	RA         bool
	Z          int
	answers    []string
	TTLs       []float64
	rejected   bool
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
			DNSEntry.ts, err = unixStrToTime(thisField.value)
			if err != nil {
				return
			}
		case "uid":
			DNSEntry.uid = thisField.value
		case "id.orig_h":
			DNSEntry.idOrigH = thisField.value
		case "id.orig_p":
			var convErr error
			DNSEntry.idOrigP, convErr = strconv.Atoi(thisField.value)
			if convErr != nil {
				err = convErr
				return
			}
		case "id.resp_h":
			DNSEntry.idRespH = thisField.value
		case "id.resp_p":
			DNSEntry.idRespP, err = strconv.Atoi(thisField.value)
			if err != nil {
				return
			}
		case "proto":
			if thisField.value == "udp" {
				DNSEntry.proto = UDP
			} else if thisField.value == "tcp" {
				DNSEntry.proto = TCP
			}
		case "trans_id":
			DNSEntry.transId, err = strconv.Atoi(thisField.value)
			if err != nil {
				return
			}
		case "rtt":
			if thisField.value == ZeekNilValue {
				DNSEntry.rtt = -1
			} else {
				DNSEntry.rtt, err = strconv.Atoi(thisField.value)
				if err != nil {
					return
				}
			}
		case "query":
			DNSEntry.query = thisField.value
		case "qclass":
			if thisField.value == ZeekNilValue {
				DNSEntry.qclass = -1
			} else {
				DNSEntry.qclass, err = strconv.Atoi(thisField.value)
				if err != nil {
					return
				}
			}
		case "qclass_name":
			DNSEntry.qclassName = thisField.value
		case "qtype":
			if thisField.value == ZeekNilValue {
				DNSEntry.qtype = -1
			} else {
				DNSEntry.qtype, err = strconv.Atoi(thisField.value)
				if err != nil {
					return
				}
			}
		case "qtype_name":
			DNSEntry.qtypeName = thisField.value
		case "rcode":
			if thisField.value == ZeekNilValue {
				DNSEntry.rcode = -1
			} else {
				DNSEntry.rcode, err = strconv.Atoi(thisField.value)
				if err != nil {
					return
				}
			}
		case "rcode_name":
			DNSEntry.rcodeName = thisField.value
		case "AA":
			DNSEntry.AA = thisField.value == "T"
		case "TC":
			DNSEntry.TC = thisField.value == "T"
		case "RD":
			DNSEntry.RD = thisField.value == "T"
		case "RA":
			DNSEntry.RA = thisField.value == "T"
		case "rejected":
			DNSEntry.rejected = thisField.value == "T"
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
				DNSEntry.answers = append(DNSEntry.answers, "")
			} else {
				splitSlice := strings.Split(thisField.value, givenHeader.setSeparator)
				DNSEntry.answers = splitSlice
			}
		case "TTLs":
			splitSlice := strings.Split(thisField.value, givenHeader.setSeparator)
			for _, thisEntry := range splitSlice {
				var thisFloat float64
				thisFloat, err = strconv.ParseFloat(thisEntry, 64)
				if err != nil {
					return
				}
				DNSEntry.TTLs = append(DNSEntry.TTLs, thisFloat)
			}
		default:
			log.Infof("unimplemented field: %s", thisField.fieldName)
		}
	}
	return
}
