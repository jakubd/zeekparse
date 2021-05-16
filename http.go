package zeekparse

import "time"

// http log format described in https://docs.zeek.org/en/master/scripts/base/protocols/http/main.zeek.html#type-HTTP::Info

type HttpEntry struct {
	TS      time.Time 		// TS:time - timestamp
	Uid     string    		// Uid:string - unique id
	IdOrigH string    		// id_orig_h:addr - senders address
	IdOrigP int       		// id_orig_p:addr - senders port
	IdRespH string    		// id_resp_h:port - responders address
	IdRespP int       		// id_resp_p:port - responders port
	// -----
	Method string			// Verb of HTTP request TODO: could be a type
	Host string				// Host header value
	Uri string				// URI of the request
	Referrer string			// Referrer header value
	Version string			// HTTP version used
	UserAgent string		// User agent of the request
	Origin string			// Origin header value
	ReqLen int				// Request body length
	RespLen int				// Response body length
	StatusCode int			// status code (if any) returned by server
	StatusMsg string		// status message (if any) returned by server
}