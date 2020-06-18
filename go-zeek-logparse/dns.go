/*
Deals with dns.log parsing specifically.  Takes constructs created in logparse.go
and generates type cast structures specifically for dns.log parsing.
*/

package zeekparse

import (
	log "github.com/sirupsen/logrus"
	"strconv"
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

type Proto string

const (
	TCP Proto = "TCP"
	UDP Proto = "UDP"
)

type DNSField struct {
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
	TTLs       []int
	rejected   bool
}

func thisLogEntryToDNSStruct(givenZeekLogEntry ZeekLogEntry) (DNSEntry DNSField, err error) {
	for _, thisField := range givenZeekLogEntry {
		switch thisField.fieldName {
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
			if thisField.value == "-" {
				DNSEntry.rtt = -1
			} else {
				DNSEntry.rtt, err = strconv.Atoi(thisField.value)
				if err != nil {
					return
				}
			}
		default:
			log.Infof("unimplmented field: %s", thisField.fieldName)
		}
	}
	return
}

// NOTE: bin this for now i don't think i can do this with mixed types
//func thisFieldToDNSStruct(givenZeekLogField ZeekLogField) (err error) {
//	return
//}
