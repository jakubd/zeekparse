package zeekparse

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"strconv"
	"time"
)

// ssl log format described in https://docs.zeek.org/en/lts/scripts/base/protocols/ssl/main.zeek.html#type-SSL::Info

// ------------------------------
// ------ Entry Structure -------
// ------------------------------

type SSLEntry struct {
	TS      time.Time 		// TS:time - timestamp
	Uid     string    		// Uid:string - unique id
	IdOrigH string    		// id_orig_h:addr - senders address
	IdOrigP int       		// id_orig_p:addr - senders port
	IdRespH string    		// id_resp_h:port - responders address
	IdRespP int       		// id_resp_p:port - responders port
	// ---------
	Version string    		// version:string - SSL/TLS version that server chose
	Cipher string     		// cipher: string - Cipher suite that server chose
	Curve string	  		// curve: string - ECDH/ECDHE curve that server chose
	ServerName string 		// server_name: string - SNI value.
	Resumed bool 			// resumed:bool - Flag to indicate if the session was resumed reusing the key material exchanged in an earlier connection.
	Established bool 		// established:bool - flag to indicate if successfully established or aborted mid-handshake.
	ServerSubject string	// subject: string - X509 subject if provided
	ServerIssuer string		// issuer: string - Signer of the X509 if provided.
	ClientSubject string 	// client_subject: string - clients x509 subject if provided.
	ClientIssuer string	 	// client_issuer: string - clients x509 issuer if provided.
	Validation string		// validation_status: string - result of validation status
}

// ------------------------------
// ----    Entry Prints   -------
// ------------------------------

func (s *SSLEntry) Print() {
	fmt.Printf("(%s) client {%s:%d} talks to {%s:%d}:\n",
		s.TS.String(), s.IdOrigH, s.IdOrigP, s.IdRespH, s.IdRespP)
	fmt.Printf("V:%s SNI: %s CIPHER:%s\n", s.Version ,s.ServerName, s.Cipher)
}

func (s *SSLEntry) ShortPrint() {
	fmt.Printf("[%s] %s:%d -> %s:%d  %s\n",
		s.TS, s.IdOrigH, s.IdOrigP, s.IdRespH, s.IdRespP,
		s.ServerName)
}

// ------------------------------
// ---- Main Parse Function -----
// ------------------------------

func thisLogEntryToSSLStruct(givenZeekLogEntry ZeekLogEntry, givenLogOpts *LogFileOpts) (SSLEntry SSLEntry, err error) {
	if len(givenLogOpts.setSeparator) == 0 {
		err = errors.New("no set seperator in header can't parse")
		return
	}

	for _, thisField := range givenZeekLogEntry {
		switch thisField.fieldName {
		case "ts":
			SSLEntry.TS, err = UnixStrToTime(thisField.value)
			if err != nil {
				return
			}
		case "uid":
			SSLEntry.Uid = thisField.value
		case "id.orig_h":
			SSLEntry.IdOrigH = thisField.value
		case "id.orig_p":
			var convErr error
			SSLEntry.IdOrigP, convErr = strconv.Atoi(thisField.value)
			if convErr != nil {
				err = convErr
				return
			}
		case "id.resp_h":
			SSLEntry.IdRespH = thisField.value
		case "id.resp_p":
			SSLEntry.IdRespP, err = strconv.Atoi(thisField.value)
			if err != nil {
				return
			}
		case "version":
			SSLEntry.Version = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "cipher":
			SSLEntry.Cipher = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "curve":
			SSLEntry.Curve = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "server_name":
			SSLEntry.ServerName = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "resumed":
			SSLEntry.Resumed = thisField.value == "T"
		case "established":
			SSLEntry.Established = thisField.value == "T"
		case "subject":
			SSLEntry.ServerSubject = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "issuer":
			SSLEntry.ServerIssuer = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "client_subject":
			SSLEntry.ClientSubject = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "client_issuer":
			SSLEntry.ClientIssuer = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "validation":
			SSLEntry.Validation = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		}
	}
	return
}

// ------------------------------
// ---- File Parse Recurse  -----
// ------------------------------

// ParseSSLLog will parse through the given single http log (passed as a filename string)
func ParseSSLLog(givenFilename string) (parsedResults []SSLEntry, err error) {
	allUnparsedEntries, header, initialParseErr := parseZeekLog(givenFilename)
	if initialParseErr != nil {
		err = initialParseErr
		return
	}
	for _, thisResult := range allUnparsedEntries {
		var sslRes SSLEntry
		sslRes, err = thisLogEntryToSSLStruct(thisResult, header)
		if err != nil {
			log.Error(err)
			return
		}
		parsedResults = append(parsedResults, sslRes)
	}
	return
}

// ParseSSLRecurse will parse through the given directory and recurse further down (passed as a directory string)
func ParseSSLRecurse(givenDirectory string) (allResults []SSLEntry, err error) {
	for thisFile := range PathRecurse(givenDirectory, "ssl") {
		thisResult, parseErr := ParseSSLLog(thisFile)
		if parseErr != nil {
			err = parseErr
			return
		}
		allResults = append(allResults, thisResult...)
	}
	return
}

// GetAllSSLForDay returns all entries on the given day from the default zeek directory as a slice of
// parsed SSLEntry objects
func GetAllSSLForDay(givenDay string, givenZeekDir ...string) (allRes []SSLEntry, err error) {
	zeekDir := GetZeekDir(givenZeekDir)
	allRes, err = ParseSSLRecurse(zeekDir + givenDay + "/")
	return
}
