package zeekparse

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"strconv"
	"strings"
	"time"
)

// conn log format described in https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info

type ConnStateObj struct {
	Code    string
	Summary string
}

func (c *ConnStateObj) Print() {
	fmt.Printf("%s:%s\n", c.Code, c.Summary)
}

func NewConnStateObj(givenCode string) *ConnStateObj {
	c := new(ConnStateObj)
	c.Code = strings.ToUpper(givenCode)
	switch c.Code {
	case "S0":
		c.Summary = "Connection attempt seen, no reply."
	case "S1":
		c.Summary = "Connection established, not terminated."
	case "SF":
		c.Summary = "Normal establishment and termination."
	case "REJ":
		c.Summary = "Connection attempt rejected."
	case "S2":
		c.Summary = "Connection established and close attempt by originator seen (but no reply from responder)."
	case "S3":
		c.Summary = "Connection established and close attempt by responder seen (but no reply from originator)."
	case "RSTO":
		c.Summary = "Connection established, originator aborted (sent a RST)."
	case "RSTR":
		c.Summary = "Responder sent a RST."
	case "RSTOS0":
		c.Summary = "Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder."
	case "RSTRH":
		c.Summary = "Responder sent a SYN ACK followed by a RST, we never saw a SYN from the (purported) originator."
	case "SH":
		c.Summary = "Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder (hence the connection was “half” open)."
	case "SHR":
		c.Summary = "Responder sent a SYN ACK followed by a FIN, we never saw a SYN from the originator."
	case "OTH":
		c.Summary = "No SYN seen, just midstream traffic (a “partial connection” that was not later closed)."
	default:
		c.Code = givenCode
		c.Summary = "ERR: unknown code"
	}
	return c
}

type ConnEntry struct {
	TS      time.Time // TS:time - timestamp
	Uid     string    // Uid:string - unique id
	IdOrigH string    // id_orig_h:addr - senders address
	IdOrigP int       // id_orig_p:addr - senders port
	IdRespH string    // id_resp_h:port - responders address
	IdRespP int       // id_resp_p:port - responders port
	Proto   Proto     // Proto:enum - protocol
	// ---------------
	Service     string       // service:str An identification of an application protocol being sent over the connection.
	Duration    float64      // duration:float64 How long the connection lasted. For 3-way or 4-way connection tear-downs, this will not include the final ACK.
	OrigBytes   int          // orig_bytes:int he number of payload bytes the originator sent. For TCP this is taken from sequence numbers and might be inaccurate (e.g., due to large connections).
	RespBytes   int          // resp_bytes:int The number of payload bytes the responder sent. See orig_bytes.
	ConnState   ConnStateObj // conn_state:ConnState
	LocalOrig   bool         // local_orig:bool If the connection is originated locally, this value will be T. If it was originated remotely it will be F. In the case that the Site::local_nets variable is undefined, this field will be left empty at all times.
	LocalResp   bool         // local_resp:bool If the connection is responded to locally, this value will be T. If it was responded to remotely it will be F. In the case that the Site::local_nets variable is undefined, this field will be left empty at all times.
	MissedBytes int          // missed_bytes:int If the connection is responded to locally, this value will be T. If it was responded to remotely it will be F. In the case that the Site::local_nets variable is undefined, this field will be left empty at all times.
	History     string       // history:str state history as string
	OrigPkts    int          // orig_pkts:int Number of packets that the originator sent. Only set if use_conn_size_analyzer = T.
	OrigIpBytes int          // orig_ip_bytes:int Number of IP level bytes that the originator sent (as seen on the wire, taken from the IP total_length header field). Only set if use_conn_size_analyzer = T.
	RespPkts    int          // resp_pkts:int Number of packets that the responder sent. Only set if use_conn_size_analyzer = T.
	RespIpBytes int          // resp_ip_bytes:int Number of IP level bytes that the responder sent (as seen on the wire, taken from the IP total_length header field). Only set if use_conn_size_analyzer = T.
	// tunnel_parents: TODO: unimplemented: If this connection was over a tunnel, indicate the uid values for any encapsulating parent connections used over the lifetime of this inner connection.
}

func (c *ConnEntry) Print() {
	fmt.Printf("(%s) client {%s:%d} talks to {%s:%d}:\n",
		c.TS.String(), c.IdOrigH, c.IdOrigP, c.IdRespH, c.IdRespP)
}

func thisLogEntryToConnStruct(givenLogEntry ZeekLogEntry, givenLogOpts *LogFileOpts) (connEntry ConnEntry, err error) {
	if len(givenLogOpts.setSeparator) == 0 {
		err = errors.New("no set seperator in header can't parse")
		return
	}

	for _, thisField := range givenLogEntry {
		switch thisField.fieldName {
		case "ts":
			connEntry.TS, err = unixStrToTime(thisField.value)
			if err != nil {
				return
			}
		case "uid":
			connEntry.Uid = thisField.value
		case "id.orig_h":
			connEntry.IdOrigH = thisField.value
		case "id.orig_p":
			var convErr error
			connEntry.IdOrigP, convErr = strconv.Atoi(thisField.value)
			if convErr != nil {
				err = convErr
				return
			}
		case "id.resp_h":
			connEntry.IdRespH = thisField.value
		case "id.resp_p":
			connEntry.IdRespP, err = strconv.Atoi(thisField.value)
			if err != nil {
				return
			}
		case "proto":
			if thisField.value == "udp" {
				connEntry.Proto = UDP
			} else if thisField.value == "tcp" {
				connEntry.Proto = TCP
			}
		default:
			log.Infof("unimplemented field: %s", thisField.fieldName)
		}
	}
	return
}
