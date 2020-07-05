package main

// big-conn.go
// -----------
// Finds all uploads in the last 3 months originating from the local network and exceeding 2500 bytes

import (
	"fmt"
	zeekparse "github.com/jakubd/go-zeek-logparse"
	"strings"
)

func main() {

	// look at the last 3 months
	for _, thisDate := range zeekparse.LastXMonths(3) {

		// get all our measurements for each day here and proceed if no error.
		allConn, err := zeekparse.GetAllConnForDay(thisDate)
		if err != nil {
			panic(err)
		}

		// set up vars here to match your network
		localSubnet := "192.168.1."
		bytesThreshold := 2500

		for _, thisConn := range allConn {

			// if the OriginatingHost is on the local subnet
			if strings.HasPrefix(thisConn.IdOrigH, localSubnet) &&
				// and the destination is not on the local subnet
				!strings.HasPrefix(thisConn.IdRespH, localSubnet) &&
				// and the destination address is not a broadcast or multicast address
				!zeekparse.IsMulticastOrBroadcastAddress(thisConn.IdRespH) &&
				// If the protocol is either TCP/UDP
				thisConn.Proto != zeekparse.NONE &&
				// and the bytesThreshold is larger than what we set
				thisConn.OrigBytes > bytesThreshold {
				// and is an upload where sentBytes > receivedBytes
				if thisConn.OrigBytes > thisConn.RespBytes {

					// then print the info to screen
					fmt.Printf("{%s} client [%s:%d] uploaded %d bytes to [%s:%d]\n", thisConn.TS.String(), thisConn.IdOrigH, thisConn.IdOrigP,
						thisConn.OrigBytes, thisConn.IdRespH, thisConn.IdRespP)
				}
			}
		}
	}
}
