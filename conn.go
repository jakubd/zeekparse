package zeekparse

import "time"

type ConnState struct {
	Code    string
	Summary string
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
	// service:str An identification of an application protocol being sent over the connection.
	// duration:float64 How long the connection lasted. For 3-way or 4-way connection tear-downs, this will not include the final ACK.
	// orig_bytes:int he number of payload bytes the originator sent. For TCP this is taken from sequence numbers and might be inaccurate (e.g., due to large connections).
	// resp_bytes:int The number of payload bytes the responder sent. See orig_bytes.
	// conn_state:ConnState
	// local_orig:bool If the connection is originated locally, this value will be T. If it was originated remotely it will be F. In the case that the Site::local_nets variable is undefined, this field will be left empty at all times.
	// local_resp:bool If the connection is responded to locally, this value will be T. If it was responded to remotely it will be F. In the case that the Site::local_nets variable is undefined, this field will be left empty at all times.
	// missed_bytes:int If the connection is responded to locally, this value will be T. If it was responded to remotely it will be F. In the case that the Site::local_nets variable is undefined, this field will be left empty at all times.
	// history:str state history as string
	// orig_pkts:int Number of packets that the originator sent. Only set if use_conn_size_analyzer = T.
	// orig_ip_bytes:int Number of IP level bytes that the originator sent (as seen on the wire, taken from the IP total_length header field). Only set if use_conn_size_analyzer = T.
	// resp_pkts:int Number of packets that the responder sent. Only set if use_conn_size_analyzer = T.
	// resp_ip_bytes:int Number of IP level bytes that the responder sent (as seen on the wire, taken from the IP total_length header field). Only set if use_conn_size_analyzer = T.
	// tunnel_parents: TODO: unimplemented If this connection was over a tunnel, indicate the uid values for any encapsulating parent connections used over the lifetime of this inner connection.
}
