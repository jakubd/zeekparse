/*
Deals with dns.log parsing specifically.  Takes constructs created in logparse.go
and generates type cast structures specifically for dns.log parsing.
*/

package zeekparse

import (
	"errors"
	"fmt"
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

// DnsEntry is a fully parsed dns.log line.
type DnsEntry struct {
	TS      time.Time // TS:time - timestamp
	Uid     string    // Uid:string - unique id
	IdOrigH string    // id_orig_h:addr - senders address
	IdOrigP int       // id_orig_p:addr - senders port
	IdRespH string    // id_resp_h:port - responders address
	IdRespP int       // id_resp_p:port - responders port
	Proto   Proto     // Proto:enum - protocol
	// ---------------
	TransId    int       // trans_id:count - identifier assigned by the program that generated the Query.
	RTT        float64   // RTT:int - round trip time for Query + resp
	Query      string    // Query:string  - the Query
	QClass     int       // QClass:count - QCLASS field in the question section
	QClassName string    // qclass_name:string - descriptive name of the QCLASS
	QType      int       // QType:count - type of record being requested (value)
	QTypeName  string    // qtype_name:string - rtype of record being requested (descriptive string)
	RCode      int       // RCode:count - response being returned (value)
	RCodeName  string    // rcode_name:string - response being returned (descriptive string)
	AA         bool      // AA:bool - authorative response (set by responder)?
	TC         bool      // TC:bool - truncated response (set by responder?
	RD         bool      // RD:bool - recursion desired (by sender)?
	RA         bool      // RA:bool - recursion available (set by responder)
	Z          int       // Z:count - reserved field (usually 0)
	Answers    []string  // Answers:vector[string] - all Answers
	TTLs       []float64 // TTLs:vector[interval] - vector of TTL of the responses lifespan in cache
	Rejected   bool      // Rejected:bool - Rejected by server?
}

// Print will just print the DNS Query and response to the screen and include the server client info.
func (thisEntry *DnsEntry) Print() {
	fmt.Printf("(%s) client {%s:%d} asks server {%s:%d}:\n",
		thisEntry.TS.String(), thisEntry.IdOrigH, thisEntry.IdOrigP, thisEntry.IdRespH, thisEntry.IdRespP)
	fmt.Printf("\t%s -> %s\n", thisEntry.Query, thisEntry.Answers)
}

// ShortPrint will just print the DNS Query and response as a one liner
func (thisEntry *DnsEntry) ShortPrint() {
	fmt.Printf("[%s] %s -> %s\n", thisEntry.TS, thisEntry.Query, thisEntry.Answers)
}

func (thisEntry *DnsEntry) IsRDNSLookup() bool {
	return strings.HasSuffix(thisEntry.Query, ".in-addr.arpa")
}

// given a zeeklogentry, it will create a DnsEntry
func thisLogEntryToDNSStruct(givenZeekLogEntry ZeekLogEntry, givenLogOpts *LogFileOpts) (DNSEntry DnsEntry, err error) {

	if len(givenLogOpts.setSeparator) == 0 {
		err = errors.New("no set seperator in header can't parse")
		return
	}

	for _, thisField := range givenZeekLogEntry {
		switch thisField.fieldName {
		case "ts":
			DNSEntry.TS, err = UnixStrToTime(thisField.value)
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
			if thisField.value == givenLogOpts.unsetField {
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
			if thisField.value == givenLogOpts.unsetField {
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
			if thisField.value == givenLogOpts.unsetField {
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
			if thisField.value == givenLogOpts.unsetField {
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
			if thisField.value == givenLogOpts.unsetField {
				DNSEntry.Z = -1
			} else {
				DNSEntry.Z, err = strconv.Atoi(thisField.value)
				if err != nil {
					return
				}
			}
		case "answers":
			if thisField.value == givenLogOpts.unsetField {
				DNSEntry.Answers = append(DNSEntry.Answers, "")
			} else {
				splitSlice := strings.Split(thisField.value, givenLogOpts.setSeparator)
				DNSEntry.Answers = splitSlice
			}
		case "TTLs":
			if thisField.value == givenLogOpts.unsetField {
				DNSEntry.TTLs = append(DNSEntry.TTLs, -1)
			} else {
				splitSlice := strings.Split(thisField.value, givenLogOpts.setSeparator)
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

// ParseDNSLog will parse through the given dns log (passed as a filename string)
func ParseDNSLog(givenFilename string) (parsedResults []DnsEntry, err error) {
	allUnparsedEntries, header, initialParseErr := parseZeekLog(givenFilename)
	if initialParseErr != nil {
		err = initialParseErr
		return
	}
	for _, thisResult := range allUnparsedEntries {
		var dnsRes DnsEntry
		dnsRes, err = thisLogEntryToDNSStruct(thisResult, header)
		if err != nil {
			log.Error(err)
			return
		}
		parsedResults = append(parsedResults, dnsRes)
	}
	return
}

// ParseDNSRecurse will parse through the given directory and recurse further down (passed as a directory string)
func ParseDNSRecurse(givenDirectory string) (allResults []DnsEntry, err error) {
	for thisFile := range PathRecurse(givenDirectory, "dns") {
		thisResult, parseErr := ParseDNSLog(thisFile)
		if parseErr != nil {
			err = parseErr
			return
		}
		allResults = append(allResults, thisResult...)
	}
	return
}

// GetAllDnsForDay returns all entries on the given day from the default zeek directory as a slice of
// parsed DnsEntry objects
func GetAllDnsForDay(givenDay string, givenZeekDir ...string) (allRes []DnsEntry, err error) {
	zeekDir := GetZeekDir(givenZeekDir)
	allRes, err = ParseDNSRecurse(zeekDir + givenDay + "/")
	return
}
