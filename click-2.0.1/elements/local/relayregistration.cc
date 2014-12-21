#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/udp.h>
#include <clicknet/ether.h>
#include "relayregistration.hh"
#include "registrationrequester.hh"
#include "registrationreplier.hh"

CLICK_DECLS

RelayRegistration::RelayRegistration(): _timer(this) {}

RelayRegistration::~RelayRegistration() {}

int RelayRegistration::configure(Vector<String> &conf, ErrorHandler *errh) {
    if(cp_va_kparse(conf, this, errh,
                    "INFOBASE", cpkP + cpkM, cpElement, &_infobase,
                    "PRIVATE_IP", cpkM, cpIPAddress, &_privateIP,
                    cpEnd) < 0) return -1;

    _timer.initialize(this);
    _timer.schedule_after_msec(1000);
    return 0;
}

void RelayRegistration::push(int, Packet *p) {
    // get relevant headers
    click_ip *ip_h = (click_ip *)p->data();
    click_udp *udp_h = (click_udp *)(ip_h + 1);
    uint32_t packet_size = p->length();

    // relay registration request
    if(packet_size == sizeof(click_ip) + sizeof(click_udp) + sizeof(registration_request_header)) {
        registration_request_header *req_h = (registration_request_header*)(udp_h + 1);
        if(req_h->type == 1) {
            // check if home address does not belong to network interface of foreign agent //TODO
            // if acting as home agent, send packet to home agent else reject with code 136 //TODO

            // If the UDP checksum is wrong then discard the packet silently.
            // The checksum is still part of the packet, which is why we check for not null, instead of checking whether what we calculate equals the checksum.
            if ((click_in_cksum_pseudohdr(click_in_cksum((unsigned char*)udp_h, packet_size - sizeof(click_ip)), ip_h, packet_size - sizeof(click_ip)) != 0) 
             && (ntohs(udp_h->uh_sum) != 0))
            {
                p->kill();
                return;
            }

            // if non-zero flags in zero-bits of request, reject with code 70 (poorly formed request)
            uint8_t flags = req_h->flags;
            if(flags != 0 || (flags >> 2) != 0) {
                // TODO send reply message
                // Packet *packet = createReply(70);
                // output(0).push(packet);
                p->kill();
                return;
            }

            // add pending request to visitor table
            visitor_entry entry;
            // link-layer source address of mobile node //TODO
            entry.ip_src = ip_h->ip_src; // mobile node Home Address
            entry.ip_dst = ip_h->ip_dst;
            entry.udp_src = ntohs(udp_h->uh_sport);
            entry.home_agent = IPAddress(req_h->home_agent);
            entry.id = req_h->id;
            entry.requested_lifetime = ntohs(req_h->lifetime);
            entry.remaining_lifetime = ntohs(req_h->lifetime);
            _infobase->pending_requests.push_back(entry);

            // relay to home agent
            WritablePacket *packet = p->uniqueify();
            click_ip *ip_head = (click_ip *)packet->data();
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
            udp_head->uh_sport = udp_h->uh_sport;
            udp_head->uh_dport = udp_h->uh_dport; // 434
            udp_head->uh_sum = htons(0);
            udp_head->uh_sum = click_in_cksum_pseudohdr(click_in_cksum((unsigned char*)udp_head, packet_size - sizeof(click_ip)), ip_head, packet_size - sizeof(click_ip));
            output(1).push(packet);
        }
    }
    // relay registration reply
    else if(packet_size = sizeof(click_ip) + sizeof(click_udp) + sizeof(registration_reply_header)) {
        registration_reply_header *rep_h = (registration_reply_header*)(udp_h + 1);
        if(rep_h->type == 3) {

            // If the UDP checksum is wrong then discard the packet silently.
            // The checksum is still part of the packet, which is why we check for not null, instead of checking whether what we calculate equals the checksum.
            if ((click_in_cksum_pseudohdr(click_in_cksum((unsigned char*)udp_h, packet_size - sizeof(click_ip)), ip_h, packet_size - sizeof(click_ip)) != 0) 
             && (ntohs(udp_h->uh_sum) != 0))
            {
                p->kill();
                return;
            }

            // if no pending request with same home address as home address in reply, discard silently
            visitor_entry entry;
            bool corresponding_request = false;
            Vector<visitor_entry>::iterator it;
            for(it = _infobase->pending_requests.begin(); it != _infobase->pending_requests.end(); ++it) {
                if(it->ip_src == IPAddress(rep_h->home_addr) /*&& it->id == rep_h->id*/) {
                    corresponding_request = true;
                    entry = *it;
                    break;
                }
            }

            if(!corresponding_request) {
                p->kill();
                return;
            }

            uint8_t code = rep_h->code;
            if(code == 0 || code == 1) {
                // add accepted registration to current visitor list
                uint16_t granted_lifetime = ntohs(rep_h->lifetime);
                if(granted_lifetime != 0) {
                    uint16_t original_lifetime = entry.requested_lifetime;
                    uint16_t lifetime = entry.remaining_lifetime - (original_lifetime - granted_lifetime);
                }
                else {
                    //TODO node is deregistering, remove from visitor list
                }
            }
             // remove pending request
            _infobase->pending_requests.erase(it);

            // relay to mobile node
            WritablePacket *packet = p->uniqueify();
            click_ip *ip_head = (click_ip *)packet->data();
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
            udp_head->uh_dport = udp_h->uh_dport;

            udp_head->uh_sum = htons(0);
            udp_head->uh_sum = click_in_cksum_pseudohdr(click_in_cksum((unsigned char*)udp_head, packet_size - sizeof(click_ip)), ip_head, packet_size - sizeof(click_ip));

            // relay to mobile node
            output(0).push(packet);
        }
    }

    p->kill();
}

void RelayRegistration::run_timer(Timer *timer) {
    // lower remaining lifetime of pending requests
    for(Vector<visitor_entry>::iterator it = _infobase->pending_requests.begin(); it != _infobase->pending_requests.end(); ++it) {
        uint16_t lifetime = ntohs(it->remaining_lifetime);
        if(it->remaining_lifetime > 1) {
            --lifetime;
            it->remaining_lifetime = htons(lifetime);
            if(it->requested_lifetime - it->remaining_lifetime > 7) {
                // if request is pending for longer than 7 seconds, send timeout reply
            	uint8_t code = 78; // Registratioin timeout
            	in_addr ip_src = it->ip_dst.in_addr(); // IP source of reply copied from destination address of corresponding Request
            	in_addr ip_dst = it->ip_src.in_addr(); // IP destination = home address from corresponding Request
            	uint16_t udp_dst = it->udp_src; // copied from UDP source port of corresponding Request
            	uint64_t id = it->id;
            	in_addr home_agent = it->home_agent.in_addr();
            	Packet *packet = createReply(code, ip_src, ip_dst, udp_dst, id, home_agent);
            	output(0).push(packet);

            	// delete pending request entry
            	_infobase->pending_requests.erase(it);
            }
        }
        else {
            // remove pending request when lifetime has expired //TODO
        }
    }

    // lower remaining lifetime for current registrations
    for(HashMap<IPAddress, visitor_entry>::iterator it = _infobase->current_registrations.begin();
            it != _infobase->current_registrations.end(); ++it) {
        //if(it->remaining_lifetime > 1) {
        //    --(it->remainig_lifetime);
        //}
       // else {

            // remove from visitor list //TODO
        //}
    }
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
	udp_head->uh_sport = 434;
	udp_head->uh_dport = udp_dst;
	uint16_t len = packet->length() - sizeof(click_ip);
	udp_head->uh_ulen = htons(len);

	// add mobile IP registration header fields
	registration_reply_header *rep_head = (registration_reply_header*)(udp_head + 1);
	rep_head->type = 3; // Registration Reply
	rep_head->code = code;
	//rep_head->lifetime = TODO this is ignored, set to 0?
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
