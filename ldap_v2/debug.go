package ldap

import (
	log "gitee.com/zhaochuninhefei/zcgolog/zclog"
	ber "gopkg.in/asn1-ber.v1"
)

// debugging type
//     - has a Printf method to write the debug output
type debugging bool

// write debug output
func (debug debugging) Printf(format string, args ...interface{}) {
	if debug {
		log.Printf(format, args...)
	}
}

func (debug debugging) PrintPacket(packet *ber.Packet) {
	if debug {
		ber.PrintPacket(packet)
	}
}
