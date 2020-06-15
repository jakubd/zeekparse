package zeekparse

import (
	"bufio"
	"compress/gzip"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"time"
)

// LogFileOpts stores vars in the header of the zeek log
type LogFileOpts struct {
	separator    string
	setSeparator string
	emptyField   string
	unsetField   string
	path         string
	open         time.Time
	fieldMapping map[string]string
}

// ZeekDateTimeFmt is the common format for zeek header datetimes
const ZeekDateTimeFmt = "2006-01-02-15-04-05"

// many zeek field values in the header will be hex encoded
// ie: tab char = \x09 convert these to real chars
func unescapeFieldValue(givenValue string) (value string) {
	if strings.HasPrefix(givenValue, "\\x") {
		separatorValueAsHexString := strings.ReplaceAll(givenValue, "\\x", "")
		separatorSlice, _ := hex.DecodeString(separatorValueAsHexString)
		if len(separatorSlice) == 1 {
			separatorUInt8 := separatorSlice[0]
			value = string(separatorUInt8)
			return
		}
	} else {
		value = givenValue
	}
	return
}

// given a string from a zeek log pull the separator character
// used to parse the rest of the logfile.
func zeekLogLineToSeparator(givenLine string) (separator string) {
	separator = ""

	if !strings.HasPrefix(givenLine, "#separator") {
		return
	}

	field, val := zeekLogPullVar(givenLine, " ")

	if field == "separator" {
		separatorValue := val
		separator = unescapeFieldValue(separatorValue)
	}

	return
}

// pull a simple space delimited variable from the zeek logs
func zeekLogPullVar(givenLine, givenSeparator string) (fieldName, fieldValue string) {
	if !strings.HasPrefix(givenLine, "#") {
		return
	}

	givenLine = strings.Replace(givenLine, "#", "", 1)
	varSplit := strings.Split(givenLine, givenSeparator)

	if len(varSplit) >= 2 {
		fieldName = varSplit[0]
		fieldValue = varSplit[1]
	}

	return
}

// determines if the given file handler is gzipped or not
// SIDE EFFECT: this moves through a file so will need to Seek back to original spot
func isThisFHndGzipped(givenFileHandler *os.File) (isGzipped bool, err error) {
	var magicByteBuffer [2]byte
	isGzipped = false

	_, thisErr := io.ReadFull(givenFileHandler, magicByteBuffer[:])
	if thisErr != nil {
		err = thisErr
	}

	// gzipped streams start with magic bytes 0x1f 0x8b
	if magicByteBuffer[0] == '\x1f' && magicByteBuffer[1] == '\x8b' {
		isGzipped = true
	}
	return
}

// set up the file handling and return a pointer to a bufio scanner
// also returns the os.File and (if exists the gzip.Reader handles)
// these should be defer closed at whatever context is needed
func setUpFileParse(givenFilename string) (scanner *bufio.Scanner, fHnd *os.File, gzipReader *gzip.Reader, err error) {
	var openErr error
	fHnd, openErr = os.Open(givenFilename)
	if openErr != nil {
		err = errors.New("open file error")
		return
	}

	gzipped, gzipErr := isThisFHndGzipped(fHnd)
	if gzipErr != nil {
		err = gzipErr
		return
	}

	// reset the seek since we read some bytes in when isThisFHndGzipped is called
	_, seekErr := fHnd.Seek(0, 0)
	if seekErr != nil {
		err = seekErr
		return
	}

	if gzipped {
		var gzReadErr error
		gzipReader, gzReadErr = gzip.NewReader(fHnd)
		if gzReadErr != nil {
			err = gzReadErr
			return
		}
		scanner = bufio.NewScanner(gzipReader)
	} else {
		scanner = bufio.NewScanner(fHnd)
	}

	return
}

// parses the header of zeek log files and returns options as the LogFileOpts struct
func parseZeekLogHeader(givenFilename string) (logfileopts *LogFileOpts, err error) {

	err = nil
	l := LogFileOpts{}
	typeMap := make(map[string]string)

	scanner, fHnd, gzipReader, fileSetupErr := setUpFileParse(givenFilename)

	if fHnd != nil {
		defer fHnd.Close()
	}
	if gzipReader != nil {
		defer gzipReader.Close()
	}

	if fileSetupErr != nil {
		err = fileSetupErr
		return
	}

	var fieldsStr, typesStr string
	for scanner.Scan() {
		thisLine := scanner.Text()

		if len(l.separator) > 0 {

			if strings.HasPrefix(thisLine, "#") {
				thisFieldName, thisFieldValue := zeekLogPullVar(thisLine, l.separator)

				if len(thisFieldName) > 0 {
					switch thisFieldName {
					case "set_separator":
						l.setSeparator = unescapeFieldValue(thisFieldValue)
					case "unset_field":
						l.unsetField = unescapeFieldValue(thisFieldValue)
					case "path":
						l.path = unescapeFieldValue(thisFieldValue)
					case "empty_field":
						l.emptyField = unescapeFieldValue(thisFieldValue)
					case "open":
						var dateParseErr error
						l.open, dateParseErr = time.Parse(ZeekDateTimeFmt, thisFieldValue)
						if dateParseErr != nil {
							err = errors.New("date not parsed for open field")
						}
					case "fields":
						fieldsStr = thisLine
					case "types":
						typesStr = thisLine
					}
				}
			}

		} else {
			// pull separator here to read the other vars from the header
			if strings.HasPrefix(thisLine, "#separator") {
				l.separator = zeekLogLineToSeparator(thisLine)
			}
		}

		if len(fieldsStr) > 0 && len(typesStr) > 0 && len(typeMap) == 0 {
			splitFields := strings.Fields(fieldsStr)
			splitTypes := strings.Fields(typesStr)

			splitFields = splitFields[1:]
			splitTypes = splitTypes[1:]

			if len(splitTypes) == len(splitFields) {
				for idx := range splitFields {
					typeMap[splitFields[idx]] = splitTypes[idx]
				}
				l.fieldMapping = typeMap
			} else {
				err = errors.New("mismatched header fields")
			}

		}

	}

	return &l, err
}
