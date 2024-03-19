#pragma once

#include <arpa/inet.h>
#include "mac.h"

#pragma pack(push, 1)
struct Dot11Hdr final {
	u_int16_t	frame_control_;
	u_int16_t	duration_;
	Mac			addr1_;
	Mac			addr2_;
	Mac			addr3_;
	u_int16_t	seq_ctrl_;

	u_int8_t	protocol_ver() const { return frame_control_ & 0x3; }
	u_int8_t	type() const { return (frame_control_ >> 2) & 0x3; }
	u_int8_t	subtype() const { return (frame_control_ >> 4) & 0xF; }
	u_int8_t	to_ds() const { return (frame_control_ >> 8) & 0x1; }
	u_int8_t	from_ds() const { return (frame_control_ >> 9) & 0x1; }
	u_int16_t	frame_control() const { return ntohs(frame_control_); }
	u_int16_t	duration() const { return ntohs(duration_); }
	u_int16_t	seq_ctrl() const { return ntohs(seq_ctrl_); }

	// type
	enum TYPE {
		MANAGEMENT = 0,
		CONTROL = 1,
		DATA = 2,
	};
	
	// subtype
	enum SUBTYPE {
		ASSOCIATION_REQUEST = 0,
		ASSOCIATION_RESPONSE = 1,
		REASSOCIATION_REQUEST = 2,
		REASSOCIATION_RESPONSE = 3,
		PROBE_REQUEST = 4,
		PROBE_RESPONSE = 5,
		BEACON = 8,
		ATIM = 9,
		DISASSOCIATION = 10,
		AUTHENTICATION = 11,
		DEAUTHENTICATION = 12,
		ACTION = 13,
		QOS_DATA = 8,
	};
};
typedef Dot11Hdr *PDot11Hdr;

#pragma pack(pop)