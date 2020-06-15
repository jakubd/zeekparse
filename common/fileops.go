package common

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
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
		if strings.HasPrefix(separatorValue, "\\x") {
			separatorValueAsHexString := strings.ReplaceAll(separatorValue, "\\x", "")
			separatorSlice, _ := hex.DecodeString(separatorValueAsHexString)
			if len(separatorSlice) == 1 {
				separatorUInt8 := separatorSlice[0]
				separator = string(separatorUInt8)
				return
			}
		} else {
			separator = separatorValue
		}
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

func parseZeekLogHeader(givenFilename string) (l LogFileOpts, err error) {
	// TODO: implement this
	// parses the header of zeek log files
	err = nil
	fHnd, openErr := os.Open(givenFilename)
	if openErr != nil {
		err = errors.New("open file error")
		return
	}

	defer fHnd.Close()

	scanner := bufio.NewScanner(fHnd)
	for scanner.Scan() {
		thisLine := scanner.Text()

		if len(l.separator) > 0 {

			if strings.HasPrefix(thisLine, "#") {
				//fmt.Println(thisLine) // these are additional headers

				thisFieldName, thisFieldValue := zeekLogPullVar(thisLine, l.separator)

				if len(thisFieldName) > 0 && thisFieldName != "separator" {
					fmt.Println(thisFieldName, thisFieldValue)
				}
			}

			//if !strings.HasPrefix(thisLine, "#") {
			//	fmt.Println(thisLine) // these are proper lines
			//}

		} else {
			// pull prefix
			if strings.HasPrefix(thisLine, "#separator") {
				l.separator = zeekLogLineToSeparator(thisLine)
			}
		}
	}

	fmt.Println("done")
	return
}