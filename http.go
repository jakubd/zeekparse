package zeekparse

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
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

	if len(thisEntry.Host) > 1 {
		fmt.Printf("HTTP %s %s http://%s:%d%s\n",
			thisEntry.Version, thisEntry.Method,thisEntry.Host, thisEntry.IdRespP, thisEntry.Uri)
	} else {
		fmt.Printf("HTTP %s %s http://%s:%d%s\n",
			thisEntry.Version, thisEntry.Method,thisEntry.IdRespH, thisEntry.IdRespP, thisEntry.Uri)
	}
}

// ShortPrint will just print the DNS Query and response as a one liner
func (thisEntry *HttpEntry) ShortPrint() {
	if len(thisEntry.Host) > 1 {
		fmt.Printf("[%s] %s -> http://%s:%d%s\n", thisEntry.TS, thisEntry.IdOrigH, thisEntry.Host, thisEntry.IdRespP, thisEntry.Uri)
	} else {
		fmt.Printf("[%s] %s -> http://%s:%d%s\n", thisEntry.TS, thisEntry.IdOrigH, thisEntry.IdRespH, thisEntry.IdRespP, thisEntry.Uri)

	}
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
			HttpEntry.ReqLen, err = strconv.Atoi(thisField.value)
			if err != nil {
				return
			}
		case "response_body_len":
			HttpEntry.RespLen, err = strconv.Atoi(thisField.value)
			if err != nil {
				return
			}
		case "status_code":

			if thisField.value == givenLogOpts.unsetField {
				HttpEntry.StatusCode = 0
			} else {
				HttpEntry.StatusCode, err = strconv.Atoi(thisField.value)
				if err != nil {
					return
				}
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

// ParseHttpLog will parse through the given http log (passed as a filename string)
func ParseHttpLog(givenFilename string) (parsedResults []HttpEntry, err error) {
	allUnparsedEntries, header, initialParseErr := parseZeekLog(givenFilename)
	if initialParseErr != nil {
		err = initialParseErr
		return
	}
	for _, thisResult := range allUnparsedEntries {
		var httpRes HttpEntry
		httpRes, err = thisLogEntryToHttpStruct(thisResult, header)
		if err != nil {
			log.Error(err)
			return
		}
		parsedResults = append(parsedResults, httpRes)
	}
	return
}

// ParseHTTPRecurse will parse through the given directory and recurse further down (passed as a directory string)
func ParseHTTPRecurse(givenDirectory string) (allResults []HttpEntry, err error) {
	for thisFile := range PathRecurse(givenDirectory, "http") {
		thisResult, parseErr := ParseHttpLog(thisFile)
		if parseErr != nil {
			err = parseErr
			return
		}
		allResults = append(allResults, thisResult...)
	}
	return
}

// GetAllHttpForDay returns all entries on the given day from the default zeek directory as a slice of
// parsed HttpEntry objects
func GetAllHttpForDay(givenDay string, givenZeekDir ...string) (allRes []HttpEntry, err error) {
	zeekDir := GetZeekDir(givenZeekDir)
	allRes, err = ParseHTTPRecurse(zeekDir + givenDay + "/")
	return
}
