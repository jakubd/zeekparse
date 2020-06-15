package common

import (
	"bufio"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"time"
)

// these are the normally included vars in the header
type LogFileOpts struct {
	separator string
	setSeparator string
	emptyField string
	unsetField string
	path string
	open time.Time
	fieldMapping map[string]string
}


const BroDateTimeFmt = "2006-01-02-03-04-05"

func UnescapeFieldValue(givenValue string) (value string) {
	// many zeek field values in the header will be hex encoded
	// ie: tab char = \x09 convert these to real chars
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

func zeekLogLineToSeparator(givenLine string) (separator string) {
	// given a string from a zeek log pull the separator character
	// used to parse the rest of the logfile.
	separator = ""

	if !strings.HasPrefix(givenLine, "#separator") {
		return
	}

	//separatorLineSplit := strings.Split(givenLine, " ")
	field, val := zeekLogPullVar(givenLine, " ")

	if field == "separator" {
		separatorValue := val
		separator = UnescapeFieldValue(separatorValue)
	}

	return
}

func zeekLogPullVar(givenLine, givenSeparator string) (fieldName, fieldValue string) {
	// pull a simple space delimited variable from the zeek logs
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

func parseZeekLogHeader(givenFilename string) (logfileopts *LogFileOpts, err error) {
	// TODO: implement this
	// parses the header of zeek log files

	err = nil
	l := LogFileOpts{}
	fHnd, openErr := os.Open(givenFilename)
	if openErr != nil {
		err = errors.New("open file error")
		return &l, err
	}
	typeMap := make(map[string]string)

	defer fHnd.Close()

	scanner := bufio.NewScanner(fHnd)
	var fieldsStr, typesStr string
	for scanner.Scan() {
		thisLine := scanner.Text()

		if len(l.separator) > 0 {

			if strings.HasPrefix(thisLine, "#") {
				thisFieldName, thisFieldValue := zeekLogPullVar(thisLine, l.separator)

				if len(thisFieldName) > 0 {
					switch thisFieldName {
					case "set_separator":
						l.setSeparator = UnescapeFieldValue(thisFieldValue)
					case "unset_field":
						l.unsetField = UnescapeFieldValue(thisFieldValue)
					case "path":
						l.path = UnescapeFieldValue(thisFieldValue)
					case "empty_field":
						l.emptyField = UnescapeFieldValue(thisFieldValue)
					case "open":
						var dateParseErr error
						l.open, dateParseErr = time.Parse(BroDateTimeFmt, thisFieldValue)
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

		if len(fieldsStr) > 0 && len(typesStr) > 0 && len(typeMap) == 0{
			splitFields := strings.Fields(fieldsStr)
			splitTypes := strings.Fields(typesStr)

			splitFields = splitFields[1:]
			splitTypes = splitTypes[1:]

			if len(splitTypes) == len(splitFields){
				for idx, _ := range splitFields {
					typeMap[splitFields[idx]] = splitTypes[idx]
				}
				l.fieldMapping = typeMap
			} else {
				err = errors.New("mismatch between fields and types in zeek log file header")
			}

		}

	}

	return &l, err
}