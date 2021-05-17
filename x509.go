package zeekparse

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"strconv"
	"time"
)

// ssl log format described in https://docs.zeek.org/en/master/scripts/base/files/x509/main.zeek.html#type-X509::Info
// and https://docs.zeek.org/en/master/scripts/base/init-bare.zeek.html#type-X509::Certificate

// ------------------------------
// ------ Entry Structure -------
// ------------------------------

type X509Entry struct {
	TS      time.Time 				// TS:time - timestamp
	Id     string    				// id:string - unique id
	// ---------
	CertVersion int					// certificate.version:count - x509 version number
	CertSerial string				// certificate.serial:string - x509 serial
	CertSubject string				// certificate.subject:string - x509 subject
	CertIssuer string				// certificate.issuer:string - x509 issuer
	CertNotValidBefore time.Time	// certificate.not_valid_before:time - timestamp when cert invalid before
	CertNotValidAfter time.Time 	// certificate.not_valid_after:time - timestamp when cert invalid after
	CertKeyAlg string				// certificate.key_alg:string - name of key algorithm
	CertSigAlg string				// certificate.sig_alg:string - name of sig algorithm
	CertKeyType string				// certificate.key_type:string - key type (rsa, dsa, etc)
	CertKeyLength int				// certificate.key_length:count - key length (bits)
}

// ------------------------------
// ----    Entry Prints   -------
// ------------------------------

func (s *X509Entry) Print() {
	fmt.Printf("(%s) %d bit %s cert: %s  validity:%s--%s issuer:%s\n",
		s.TS.String(), s.CertKeyLength, s.CertKeyType ,s.CertSubject,
		s.CertNotValidBefore.Format("01/02/06"), s.CertNotValidAfter.Format("01/02/06"),
		s.CertIssuer)
}

func (s *X509Entry) ShortPrint() {
	fmt.Printf("[%s]%s\n",
		s.TS, s.CertSubject)
}

// ------------------------------
// ---- Main Parse Function -----
// ------------------------------

func thisLogEntryToX509Struct(givenZeekLogEntry ZeekLogEntry, givenLogOpts *LogFileOpts) (X509Entry X509Entry, err error) {
	if len(givenLogOpts.setSeparator) == 0 {
		err = errors.New("no set seperator in header can't parse")
		return
	}

	for _, thisField := range givenZeekLogEntry {
		switch thisField.fieldName {
		case "ts":
			X509Entry.TS, err = UnixStrToTime(thisField.value)
			if err != nil {
				return
			}
		case "id":
			X509Entry.Id = thisField.value
		case "certificate.version":
			X509Entry.CertVersion, err = strconv.Atoi(thisField.value)
			if err != nil {
				return
			}
		case "certificate.serial":
			X509Entry.CertSerial = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "certificate.subject":
			X509Entry.CertSubject = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "certificate.issuer":
			X509Entry.CertIssuer = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "certificate.not_valid_before":
			X509Entry.CertNotValidBefore, err = UnixStrToTime(thisField.value)
			if err != nil {
				return
			}
		case "certificate.not_valid_after":
			X509Entry.CertNotValidAfter, err = UnixStrToTime(thisField.value)
			if err != nil {
				return
			}
		case "certificate.key_alg":
			X509Entry.CertKeyAlg = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "certificate.sig_alg":
			X509Entry.CertSigAlg = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "certificate.key_type":
			X509Entry.CertKeyType = StrBlankIfUnset(thisField.value, givenLogOpts.unsetField)
		case "certificate.key_length":
			X509Entry.CertKeyLength, err = strconv.Atoi(thisField.value)
			if err != nil {
				return
			}
		}
	}
	return
}

// ------------------------------
// ---- File Parse Recurse  -----
// ------------------------------


// ParseX509Log will parse through the given single x509 log (passed as a filename string)
func ParseX509Log(givenFilename string) (parsedResults []X509Entry, err error) {
	allUnparsedEntries, header, initialParseErr := parseZeekLog(givenFilename)
	if initialParseErr != nil {
		err = initialParseErr
		return
	}
	for _, thisResult := range allUnparsedEntries {
		var x509Res X509Entry
		x509Res, err = thisLogEntryToX509Struct(thisResult, header)
		if err != nil {
			log.Error(err)
			return
		}
		parsedResults = append(parsedResults, x509Res)
	}
	return
}

// ParseX509Recurse will parse through the given directory and recurse further down (passed as a directory string)
func ParseX509Recurse(givenDirectory string) (allResults []X509Entry, err error) {
	for thisFile := range PathRecurse(givenDirectory, "x509") {
		thisResult, parseErr := ParseX509Log(thisFile)
		if parseErr != nil {
			err = parseErr
			return
		}
		allResults = append(allResults, thisResult...)
	}
	return
}

// GetAllX509ForDay returns all entries on the given day from the default zeek directory as a slice of
// parsed X509Entry objects
func GetAllX509ForDay(givenDay string, givenZeekDir ...string) (allRes []X509Entry, err error) {
	zeekDir := GetZeekDir(givenZeekDir)
	allRes, err = ParseX509Recurse(zeekDir + givenDay + "/")
	return
}