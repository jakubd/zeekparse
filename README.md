[![Actions Status](https://github.com/jakubd/go-zeek-logparse/workflows/Test/badge.svg)](https://github.com/jakubd/go-zeek-logparse/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/jakubd/go-zeek-logparse)](https://goreportcard.com/report/github.com/jakubd/go-zeek-logparse)
[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

# go-zeek-logparse

A work-in-progress log parser for common zeek text logs in Go.

# Use Case

This was made because I want to do data analysis on network logs I have been collecting 
which are mostly in Zeek/Bro IDS text format.  These are compact files and can be retained 
for a longer period  compared to full packet captures.  Analyzing them quickly is typically
done with `zeekcut` but I wanted to have more control over the logic in order to make it 
repeatable.  This is what `go-zeek-logparse` is meant to do; parse the text logs that Zeek 
creates by default so that you can write your logic and analyze them in Go.

My plan is to support these logs: dns, conn, http, ssl, ssh and dhcp. 

# Status of WIP

* [X] handles gz compressed and uncompressed files
* [X] Can parse values from headers.
* [X] Can parse log entries into Go structures.
* [x] Can parse dns.log entries.
* [x] Can parse conn.log entries.

# Logs that might be useful some day 
* [ ] Can parse http.log entries.
* [ ] Can parse ssl.log entries.
* [ ] Can parse ssh.log entries.
* [ ] Can parse dhcp.log entries. 