#pragma once

#include <cstdint>
#include <arpa/inet.h>

#pragma pack(push, 1)
struct TcpHdr final {
	uint16_t			sport_;
	uint16_t			dport_;
	uint32_t			seq_;
	uint32_t			ack_;
	uint8_t				off_;
	uint8_t				flags_;
	uint16_t			win_;
	uint16_t			sum_;
	uint16_t			urp_;

	uint16_t			sport() { return ntohs(sport_); }
	uint16_t			dport() { return ntohs(dport_); }
	uint32_t			seqno() { return ntohl(seq_); }
	uint32_t			ackno() { return ntohl(ack_); }
	uint8_t				off() { return (off_ & 0xF0) >> 4; }
	uint8_t				flags() { return flags_ & 0x3F; }
	uint16_t			win() { return ntohs(win_); }
	uint16_t			sum() { return ntohs(sum_); }
	uint16_t			urp() { return ntohs(urp_); }

	//flag
	static const uint8_t	FIN = 0x01;
	static const uint8_t	SYN = 0x02;
	static const uint8_t	RST = 0x04;
	static const uint8_t	PSH = 0x08;
	static const uint8_t	ACK = 0x10;
	static const uint8_t	URG = 0x20;
};
typedef TcpHdr *PTcpHdr;
#pragma pack(pop)
