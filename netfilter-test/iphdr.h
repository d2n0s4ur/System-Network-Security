#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
	uint8_t				v_ihl_;
	uint8_t				tos_;
	uint16_t			tlen_;
	uint16_t			ident_;
	uint16_t			flag_off_;
	uint8_t				ttl_;
	uint8_t				proto_;
	uint16_t			sum_;
	Ip					sip_;
	Ip					dip_;

	uint8_t 			v() { return (v_ihl_ & 0xF0) >> 4; }
	uint8_t 			hl() { return v_ihl_ & 0x0F; }
	uint8_t 			tos() { return tos_; }
	uint16_t 			tlen() { return ntohs(tlen_); }
	uint16_t 			ident() { return ntohs(ident_); }
	uint16_t 			off() { return ntohs(flag_off_); }
	uint8_t 			ttl() { return ttl_; }
	uint8_t 			proto() { return proto_; }
	uint16_t 			sum() { return ntohs(sum_); }

	Ip					sip() { return ntohl(sip_); }
	Ip					dip() { return ntohl(dip_); }

	//protocol
	static const uint8_t	ICMP = 0x01;
	static const uint8_t	TCP = 0x06;
	static const uint8_t	UDP = 0x11;
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)
