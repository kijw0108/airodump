#pragma once

#include <cstdint>
#include<cstdio>
#include "mac.h"

#pragma pack(push, 1)
struct radiotap_header
{
	uint8_t it_version;
	uint8_t it_pad;
	uint16_t it_len;
	uint32_t it_present;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct beacon_header
{
	uint8_t type;
	uint8_t flags;
	uint16_t duration;
	Mac daddr;
	Mac saddr;
	Mac bssid;
	uint16_t sequence;
	/*void print(){
		printf("%02x ",type);
		printf("%02x ",flags);
		printf("%04x ",duration);
	}*/
};
#pragma pack(pop)

#pragma pack(push, 1)
struct beacon_fixed
{
	uint64_t timestamp;
	uint16_t interval;
	uint16_t capa_info;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct beacon_ssid
{
	uint8_t num;
	uint8_t len;
	char essid[32];
};
#pragma pack(pop)
