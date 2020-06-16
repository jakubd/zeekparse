package zeekparse

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"strings"
)

// a generic zeek log field without casts
type ZeekLogField struct {
	fieldName string
	fieldType string
	value     string
}

// a zeek log entry is a slice of fields referring to a single row in a log
type ZeekLogEntry []ZeekLogField

func parseZeekLog(givenFilename string) (allResults []ZeekLogEntry, err error) {
	fmt.Println(givenFilename)
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

	headerInfo, headerParseErr := parseZeekLogHeader(givenFilename)
	if headerParseErr != nil {
		err = headerParseErr
		return
	}

	for scanner.Scan() {
		thisLine := scanner.Text()
		if !strings.HasPrefix(thisLine, "#") {
			var thisEntry ZeekLogEntry
			thisLineSplit := strings.Split(thisLine, headerInfo.separator)
			if len(thisLineSplit) != len(headerInfo.fieldOrder) {
				err = errors.New("mismatch between line in log and fields in header")
				return
			}

			for idx, fieldName := range headerInfo.fieldOrder {
				var thisField = ZeekLogField{
					fieldName: fieldName,
					fieldType: headerInfo.fieldTypeMap[fieldName],
					value:     thisLineSplit[idx],
				}
				thisEntry = append(thisEntry, thisField)
				log.Debugf("#%d: [%s:%s] %s", idx, fieldName, headerInfo.fieldTypeMap[fieldName], thisLineSplit[idx])
			}
			log.Debug(thisLineSplit)
			allResults = append(allResults, thisEntry)
		}
	}

	return
}