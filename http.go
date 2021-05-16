package zeekparse

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// http log format described in https://docs.zeek.org/en/master/scripts/base/protocols/http/main.zeek.html#type-HTTP::Info

type HttpEntry struct {
	TS      time.Time 		// TS:time - timestamp
	Uid     string    		// Uid:string - unique id
	IdOrigH string    		// id_orig_h:addr - senders address
	IdOrigP int       		// id_orig_p:addr - senders port
	IdRespH string    		// id_resp_h:port - responders address
	IdRespP int       		// id_resp_p:port - responders port
	// -----
	Method string			// method:string - Verb of HTTP request
	Host string				// host:string - Host header value
	Uri string				// uri:string - URI of the request
	Referrer string			// referrer:string - Referrer header value
	Version string			// version:string - HTTP version used
	UserAgent string		// user_agent:string - User agent of the request
	Origin string			// origin:string - Origin header value
	ReqLen int				// request_body_len:count - Request body length
	RespLen int				// response_body_len:count - Response body length
	StatusCode int			// status_code: count - status code (if any) returned by server
	StatusMsg string		// status_msg:string - status message (if any) returned by server
	MimeTypes []string		// orig_mime_types:vector[string] - mime types in resp (can be more than one)
}

func (thisEntry *HttpEntry) Print() {
	fmt.Printf("(%s) client {%s:%d} asks server {%s:%d}:\n",
		thisEntry.TS.String(), thisEntry.IdOrigH, thisEntry.IdOrigP, thisEntry.IdRespH, thisEntry.IdRespP)
	fmt.Printf("HTTP %s %s http://%s:%d%s\n",
		thisEntry.Version, thisEntry.Method,thisEntry.Host, thisEntry.IdRespP, thisEntry.Uri)
}

// ShortPrint will just print the DNS Query and response as a one liner
func (thisEntry *HttpEntry) ShortPrint() {
	fmt.Printf("[%s] %s -> http://%s:%d%s\n", thisEntry.TS, thisEntry.IdOrigH, thisEntry.Host, thisEntry.IdRespP, thisEntry.Uri)
}

func thisLogEntryToHttpStruct(givenZeekLogEntry ZeekLogEntry, givenLogOpts *LogFileOpts) (HttpEntry HttpEntry, err error) {
	if len(givenLogOpts.setSeparator) == 0 {
		err = errors.New("no set seperator in header can't parse")
		return
	}

	for _, thisField := range givenZeekLogEntry {
		switch thisField.fieldName {
		case "ts":
			HttpEntry.TS, err = UnixStrToTime(thisField.value)
			if err != nil {
				return
			}
		case "uid":
			HttpEntry.Uid = thisField.value
		case "id.orig_h":
			HttpEntry.IdOrigH = thisField.value
		case "id.orig_p":
			var convErr error
			HttpEntry.IdOrigP, convErr = strconv.Atoi(thisField.value)
			if convErr != nil {
				err = convErr
				return
			}
		case "id.resp_h":
			HttpEntry.IdRespH = thisField.value
		case "id.resp_p":
			HttpEntry.IdRespP, err = strconv.Atoi(thisField.value)
			if err != nil {
				return
			}
		case "method":
			HttpEntry.Method = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "host":
			HttpEntry.Host = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "uri":
			HttpEntry.Uri = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "referrer":
			HttpEntry.Referrer = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "version":
			HttpEntry.Version = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "user_agent":
			HttpEntry.UserAgent = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "origin":
			HttpEntry.Origin = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "request_body_len":
			HttpEntry.ReqLen, err = IntOrError(thisField.value)
			if err != nil {
				return
			}
		case "response_body_len":
			HttpEntry.RespLen, err = IntOrError(thisField.value)
			if err != nil {
				return
			}
		case "status_code":
			HttpEntry.StatusCode, err = IntOrError(thisField.value)
			if err != nil {
				return
			}
		case "status_msg":
			HttpEntry.StatusMsg = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "orig_mime_types":
			if thisField.value == givenLogOpts.unsetField {
				HttpEntry.MimeTypes = append(HttpEntry.MimeTypes, "")
			} else {
				splitSlice := strings.Split(thisField.value, givenLogOpts.setSeparator)
				HttpEntry.MimeTypes = splitSlice
			}
		}
	}
	return
}