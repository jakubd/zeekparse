/*
Deals with dns.log parsing specifically.  Takes constructs created in logparse.go
and generates type cast structures specifically for dns.log parsing.
*/

package zeekparse

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

func thisLogEntryToDNSStruct(givenZeekLogEntry ZeekLogEntry) (err error) {
	return
}

func thisFieldToDNSStruct(givenZeekLogField ZeekLogField) (err error) {
	return
}
