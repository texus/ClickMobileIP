#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/udp.h>
#include <clicknet/ether.h>
#include <clicknet/icmp.h>
#include "relayregistration.hh"
#include "registrationrequester.hh"
#include "registrationreplier.hh"

namespace {
uint64_t ntohll(uint64_t value)
{
	int num = 42;
	if (*(char *)&num == 42) {
		uint32_t high_part = ntohl((uint32_t)(value >> 32));
		uint32_t low_part = ntohl((uint32_t)(value & 0xFFFFFFFFLL));
		return (((uint64_t)low_part) << 32) | high_part;
	} else {
		return value;
	}
}

uint64_t htonll(uint64_t value)
{
	int num = 42;
	if (*(char *)&num == 42) {
		uint32_t high_part = htonl((uint32_t)(value >> 32));
		uint32_t low_part = htonl((uint32_t)(value & 0xFFFFFFFFLL));
		return (((uint64_t)low_part) << 32) | high_part;
	} else {
		return value;
	}
}
}

CLICK_DECLS

RelayRegistration::RelayRegistration(): _timer(this), _maxRegistrations(-1) {}

RelayRegistration::~RelayRegistration() {}

int RelayRegistration::configure(Vector<String> &conf, ErrorHandler *errh) {
	if(cp_va_kparse(conf, this, errh,
			"INFOBASE", cpkP + cpkM, cpElement, &_infobase,
			"PRIVATE_IP", cpkM, cpIPAddress, &_privateIP,
			"MAX_REGISTRATIONS", cpkN, cpInteger, &_maxRegistrations,
			cpEnd) < 0) return -1;

	_timer.initialize(this);
	_timer.schedule_after_msec(1000);
	return 0;
}

void RelayRegistration::push(int, Packet *p) {
	// get relevant headers
	click_ether *eth_h = (click_ether *)p->data();
	click_ip *ip_h = (click_ip *)(eth_h + 1);
	uint32_t packet_size = p->length() - sizeof(click_ether);

	// check if ICMP error message
	if (ip_h->ip_p == 1) {
		click_icmp *icmp_h = (click_icmp *)(ip_h + 1);
		click_ip *old_ip_h = (click_ip *)(icmp_h + 1); // IP header of packet that caused the error
		uint8_t type = icmp_h->icmp_type;
		// if HA unreachable, send Reply to MNs that sent request to this HA, denying request
		if (type == 3) {
			IPAddress home_agent = IPAddress(old_ip_h->ip_dst);
			uint8_t icmp_code = icmp_h->icmp_code;
			uint8_t code;
			switch(icmp_code) {
			case 0: // home network unreachable
				code = 80;
				break;
			case 1: // home agent host unreachable
				code = 81;
				break;
			case 3: // home agent port unreachable
				code = 82;
				break;
			default: // other ICMP error
				code = 88;
				break;
			}

			for(Vector<visitor_entry>::iterator it = _infobase->pending_requests.begin(); it != _infobase->pending_requests.end();) {
				if(it->home_agent == home_agent) {
					// send reply
					in_addr ip_src = it->ip_dst;
					in_addr ip_dst = it->ip_src;
					uint16_t udp_dst = it->udp_src;
					uint64_t id = it->id;
					Packet *packet = createReply(code, ip_src, ip_dst, udp_dst, id, home_agent.in_addr());
					_infobase->pending_requests.erase(it);
					output(0).push(packet);
				}
				else
				    ++it;
			}
		}
	}
	else {
		click_udp *udp_h = (click_udp *)(ip_h + 1);

		// relay registration request
		if(packet_size == sizeof(click_ip) + sizeof(click_udp) + sizeof(registration_request_header)) {
			registration_request_header *req_h = (registration_request_header*)(udp_h + 1);
			if(req_h->type == 1) {
				relayRequest(p);
			}
		}
		// relay registration reply
		else if(packet_size == sizeof(click_ip) + sizeof(click_udp) + sizeof(registration_reply_header)) {
			registration_reply_header *rep_h = (registration_reply_header*)(udp_h + 1);
			if(rep_h->type == 3) {
				relayReply(p);
			}
		}
	}

	p->kill();
}

void RelayRegistration::run_timer(Timer *timer) {

	// lower remaining lifetime of pending requests
	for(Vector<visitor_entry>::iterator it = _infobase->pending_requests.begin(); it != _infobase->pending_requests.end();) {
		uint16_t lifetime = ntohs(it->remaining_lifetime);
		if(it->remaining_lifetime > 0) {
			--lifetime;
			it->remaining_lifetime = htons(lifetime);
			if(it->requested_lifetime - it->remaining_lifetime > 7) {
				// if request is pending for longer than 7 seconds, send timeout reply
				uint8_t code = 78; // Registratioin timeout
				in_addr ip_src = it->ip_dst.in_addr(); // IP source of reply copied from destination address of corresponding Request
				in_addr ip_dst = it->ip_src.in_addr(); // IP destination = home address from corresponding Request
				uint16_t udp_dst = it->udp_src; // copied from UDP source port of corresponding Request
				uint64_t id = htonll(it->id);
				in_addr home_agent = it->home_agent.in_addr();
				Packet *packet = createReply(code, ip_src, ip_dst, udp_dst, id, home_agent);
				output(0).push(packet);

				// delete pending request entry
				it = _infobase->pending_requests.erase(it);
			}
			else
				++it;
		}
		else {
			// remove pending request when lifetime has expired
			it = _infobase->pending_requests.erase(it);
		}
	}

	// lower remaining lifetime for current registrations
	for(HashTable<IPAddress, visitor_entry>::iterator it = _infobase->current_registrations.begin(); it != _infobase->current_registrations.end();) {
        if(it->remaining_lifetime > 0) {
            --(it->remainig_lifetime);
            ++it;
        }
        else {
            it = _infobase->current_registrations.erase(it);
        }
	}

	timer->schedule_after_msec(1000);
}

void RelayRegistration::relayRequest(Packet *p) {
	// get relevant headers
	click_ether *eth_h = (click_ether *)p->data();
	click_ip *ip_h = (click_ip *)(eth_h + 1);
	click_udp *udp_h = (click_udp *)(ip_h + 1);
	registration_request_header *req_h = (registration_request_header *)(udp_h + 1);
	uint32_t packet_size = p->length() - sizeof(click_ether);

	// If the UDP checksum is wrong then discard the packet silently.
	// The checksum is still part of the packet, which is why we check for not null, instead of checking whether what we calculate equals the checksum.
	if ((click_in_cksum_pseudohdr(click_in_cksum((unsigned char*)udp_h, packet_size - sizeof(click_ip)), ip_h, packet_size - sizeof(click_ip)) != 0)
			&& (ntohs(udp_h->uh_sum) != 0))
	{
		p->kill();
		return;
	}

	// if FA already has maximum number of MNs registered, reject with code 66 (insufficient resources)
	int num_current_registrations = _infobase->current_registrations.size();
	if(_maxRegistrations > -1 && num_current_registrations >= _maxRegistrations) {
		uint8_t code = 66;
		in_addr ip_src = ip_h->ip_dst;
		in_addr ip_dst = ip_h->ip_src;
		uint16_t udp_dst = udp_h->uh_sport;
		uint64_t identification = req_h->id;
		in_addr home_agent = *(struct in_addr *)&req_h->home_agent;
		Packet *packet = createReply(code, ip_src, ip_dst, udp_dst, identification, home_agent);
		output(0).push(packet);
		p->kill();
		return;
	}

	// if non-zero flags in zero-bits of request, reject with code 70 (poorly formed request)
	uint8_t flags = req_h->flags;
	if((flags & 1) || ((flags >> 2) & 1)) {
		uint8_t code = 70;
		in_addr ip_src = ip_h->ip_dst;
		in_addr ip_dst = ip_h->ip_src;
		uint16_t udp_dst = udp_h->uh_sport;
		uint64_t identification = req_h->id;
		in_addr home_agent = *(struct in_addr *)&req_h->home_agent;
		Packet *packet = createReply(code, ip_src, ip_dst, udp_dst, identification, home_agent);
		output(0).push(packet);
		p->kill();
		return;
	}

	// since our FA's do not support co-located care of addresses, GRE-encapsulation and Minimal encapsulation, mobile nodes requesting these
	// will have their requests denied
	if(((flags >> 3) & 1) || ((flags >> 4) & 1)) {
		uint8_t code = 72; // requested encapsulation unavailable
		in_addr ip_src = ip_h->ip_dst;
		in_addr ip_dst = ip_h->ip_src;
		uint16_t udp_dst = udp_h->uh_sport;
		uint64_t identification = req_h->id;
		in_addr home_agent = *(struct in_addr *)&req_h->home_agent;
		Packet *packet = createReply(code, ip_src, ip_dst, udp_dst, identification, home_agent);
		output(0).push(packet);
		p->kill();
		return;
	}

	// add pending request to visitor table
	visitor_entry entry;
	entry.eth_src = EtherAddress(eth_h->ether_shost);
	entry.ip_src = ip_h->ip_src; // mobile node Home Address
	entry.ip_dst = ip_h->ip_dst;
	entry.udp_src = ntohs(udp_h->uh_sport);
	entry.home_agent = IPAddress(req_h->home_agent);
	entry.id = ntohll(req_h->id);
	entry.requested_lifetime = ntohs(req_h->lifetime);
	entry.remaining_lifetime = ntohs(req_h->lifetime);
	_infobase->pending_requests.push_back(entry);

	// relay to home agent
	WritablePacket *packet = p->uniqueify();
	click_ether *eth_head = (click_ether *)packet->data();
	click_ip *ip_head = (click_ip *)(eth_head + 1);
	click_udp *udp_head = (click_udp *)(ip_head + 1);
	// set IP fields
	ip_head->ip_len = htons(packet_size);
	ip_head->ip_ttl = 64;
	ip_head->ip_src = _infobase->address;
	IPAddress dst = IPAddress(req_h->home_agent);
	ip_head->ip_dst = dst.in_addr();
	// set annotation
	packet->set_dst_ip_anno(ip_head->ip_dst);
	// set UDP fields
	udp_head->uh_sport = htons(rand() % (65535 - 49152) + 49152);
	udp_head->uh_dport = udp_h->uh_dport; // 434
	udp_head->uh_sum = htons(0);
	udp_head->uh_sum = click_in_cksum_pseudohdr(click_in_cksum((unsigned char*)udp_head, packet_size - sizeof(click_ip)), ip_head, packet_size - sizeof(click_ip));

	output(1).push(packet);
}

void RelayRegistration::relayReply(Packet *p) {

	// get relevant headers
	click_ether *eth_h = (click_ether *)p->data();
	click_ip *ip_h = (click_ip *)(eth_h + 1);
	click_udp *udp_h = (click_udp *)(ip_h + 1);
	registration_reply_header *rep_h = (registration_reply_header *)(udp_h + 1);
	uint32_t packet_size = p->length() - sizeof(click_ether);

	// If the UDP checksum is wrong then discard the packet silently.
	// The checksum is still part of the packet, which is why we check for not null, instead of checking whether what we calculate equals the checksum.
	if ((click_in_cksum_pseudohdr(click_in_cksum((unsigned char*)udp_h, packet_size - sizeof(click_ip)), ip_h, packet_size - sizeof(click_ip)) != 0)
			&& (ntohs(udp_h->uh_sum) != 0))
	{
		p->kill();
		return;
	}

	// if no pending request with same home address as home address in reply, discard silently
	Vector<visitor_entry>::iterator entry;
	bool corresponding_request = false;
	for(Vector<visitor_entry>::iterator it = _infobase->pending_requests.begin(); it != _infobase->pending_requests.end(); ++it) {
		if(it->ip_src == IPAddress(rep_h->home_addr)) {
			// pending request with same home address as in reply is found
			corresponding_request = true;
			entry = it;
			break;
		}
	}

	if(!corresponding_request) {
		p->kill();
		return;
	}

	// if lower 32 bits of Identification fields do not match, discard silently
	if((uint32_t)(htonll(entry->id) & 0xFFFFFFFFLL) != (uint32_t)(rep_h->id & 0xFFFFFFFFLL)) {
		p->kill();
		return;
	}

	uint8_t code = rep_h->code;
	if(code == 0 || code == 1) {
		// the request was accepted
		uint16_t granted_lifetime = ntohs(rep_h->lifetime);
		// if lifetime != 0 change visitor entry & delete pending request
		if(granted_lifetime != 0) {
			const IPAddress mn_home_addr = IPAddress(rep_h->home_addr);
			// create visitor entry
			// put new visitor entry in visitor list
			// (if it exists, old visitor list entry with same home address will be overwritten, i.e. updated)
			visitor_entry new_entry = *entry;
			new_entry.remaining_lifetime = rep_h->lifetime; // set to granted lifetime, so FA does not time out befor MN
			_infobase->current_registrations.set(mn_home_addr, new_entry);
		}
		// if lifetime == 0 delete visitor entry & pending request
		else {
			// look in current registrations
			// if present, remove current visitor list entry
			const IPAddress mn_home_addr = IPAddress(rep_h->home_addr);
			_infobase->current_registrations.erase(mn_home_addr);
		}
		//	} else { // request was denied by the home agent
	}

	// delete pending request
	_infobase->pending_requests.erase(entry);

	// relay the reply to the mobile node
	WritablePacket *packet = p->uniqueify();
	click_ether *eth_head = (click_ether *)packet->data();
	click_ip *ip_head = (click_ip *)(eth_head + 1);
	click_udp *udp_head = (click_udp *)(ip_head + 1);

	// set IP fields
	ip_head->ip_src = _privateIP;
	IPAddress dst = IPAddress(rep_h->home_addr);
	ip_head->ip_dst = dst.in_addr();

	// set annotations
	packet->set_dst_ip_anno(ip_head->ip_dst);

	// set UDP fields
	uint16_t udp_src_prt = ntohs(udp_h->uh_sport);
	udp_head->uh_sport = udp_h->uh_sport;
	udp_head->uh_dport = htons(entry->udp_src);

	udp_head->uh_sum = htons(0);
	udp_head->uh_sum = click_in_cksum_pseudohdr(click_in_cksum((unsigned char*)udp_head, packet_size - sizeof(click_ip)), ip_head, packet_size - sizeof(click_ip));

	// relay to mobile node
	packet->pull(14);
	output(0).push(packet);
}

Packet* RelayRegistration::createReply(uint8_t code, in_addr ip_src, in_addr ip_dst, uint16_t udp_dst,
		uint64_t id, in_addr home_agent) {
	int packet_size = sizeof(click_ip) + sizeof(click_udp) + sizeof(registration_reply_header);
	int headroom = sizeof(click_ether);
	WritablePacket *packet = Packet::make(headroom, 0, packet_size, 0);

	if (packet == 0) {
		click_chatter("Could not make packet");
		return 0;
	}

	memset(packet->data(), 0, packet->length());

	// add IP header
	click_ip *ip_head = (click_ip*)packet->data();
	ip_head->ip_v = 4;
	ip_head->ip_hl = 5;
	ip_head->ip_tos = 0; // Best-Effort
	ip_head->ip_len = htons(packet_size);
	ip_head->ip_ttl = 64;
	ip_head->ip_p = 17; // UDP protocol
	ip_head->ip_src = ip_src;
	ip_head->ip_dst = ip_dst;
	ip_head->ip_sum = click_in_cksum((unsigned char*)ip_head, sizeof(click_ip));

	// set destination in annotation
	packet->set_dst_ip_anno(ip_dst);

	// add UDP header
	click_udp *udp_head = (click_udp*)(ip_head + 1);
	udp_head->uh_sport = htons(434);
	udp_head->uh_dport = htons(udp_dst);
	uint16_t len = packet->length() - sizeof(click_ip);
	udp_head->uh_ulen = htons(len);

	// add mobile IP registration header fields
	registration_reply_header *rep_head = (registration_reply_header*)(udp_head + 1);
	rep_head->type = 3; // Registration Reply
	rep_head->code = code;
	rep_head->lifetime = 0; // ignored at reception since code > 1
	rep_head->home_addr = ip_dst.s_addr;
	rep_head->id = id;
	rep_head->home_agent = home_agent.s_addr;

	// calculate UDP checksum
	udp_head->uh_sum = click_in_cksum_pseudohdr
			(click_in_cksum((unsigned char*)udp_head, packet_size - sizeof(click_ip)), ip_head, packet_size - sizeof(click_ip));

	return packet;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RelayRegistration)
