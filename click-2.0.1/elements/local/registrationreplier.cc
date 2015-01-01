#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/udp.h>
#include "registrationreplier.hh"
#include "registrationrequester.hh"

CLICK_DECLS

IPAddress RegistrationReplier::_allMobileAgentsAddress = IPAddress("255.255.255.255");

RegistrationReplier::RegistrationReplier() {}

RegistrationReplier::~RegistrationReplier() {}

int RegistrationReplier::configure(Vector<String>& conf, ErrorHandler *errh) {
    if(cp_va_kparse(conf, this, errh, "INFOBASE", cpkP + cpkM, cpElement, &_infobase, cpEnd) < 0)
        return -1;

    return 0;
}

void RegistrationReplier::push(int, Packet *p) {
    // it is assumed that all incoming packets are registration requests
    // get relevant headers
    click_ip *req_ip = (click_ip*)p->data();
    click_udp *req_udp = (click_udp*)(req_ip + 1);
    registration_request_header *req_rh = (registration_request_header*)(req_udp + 1);

    if(req_rh->type == 1) {
        // decide to accept or deny
        uint8_t code = check_acceptability(p);

        // if accepted, save info into homeagentinfobase
        if (code == 0 || code == 1)
        {
            if (req_rh->home_addr == req_rh->co_addr)
            {
                // Remove any entry of this mobile node on a foreign network
                for (unsigned int i = 0; i < _infobase->mobileNodesInfo.size();)
                {
                    if (_infobase->mobileNodesInfo[i].address == IPAddress(req_rh->home_addr))
                    {
                        _infobase->mobileNodesInfo.erase(_infobase->mobileNodesInfo.begin() + i);
                        continue;
                    }

                    ++i;
                }
            }
            else
            {
                MobileNodeInfo info; //TODO check if all info correct
                info.address = IPAddress(req_rh->home_addr);
                info.careOfAddress = IPAddress(req_rh->co_addr);
                info.identification = req_rh->id;
                info.remainingLifetime = req_rh->lifetime;
                _infobase->mobileNodesInfo.push_back(info);
            }
        }

        // send reply
        int packet_size = sizeof(click_ip) + sizeof(click_udp) + sizeof(registration_reply_header);
        int headroom = sizeof(click_ether);
        WritablePacket *packet = Packet::make(headroom, 0, packet_size, 0);

        // Check if packet correctly created
        if(packet == 0) {
            click_chatter("Could not make packet");
            return;
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
        ip_head->ip_src = req_ip->ip_dst; // copied from destination address of the Registration Request
        ip_head->ip_dst = req_ip->ip_src; // copied form source address of Registration Request to wich agent is replying
        ip_head->ip_sum = click_in_cksum((unsigned char*)ip_head, sizeof(click_ip));

        // set destination in annotation
        packet->set_dst_ip_anno(ip_head->ip_dst);

        // add UDP header
        click_udp *udp_head = (click_udp*)(ip_head + 1);
        udp_head->uh_sport = req_udp->uh_dport; // 434
        udp_head->uh_dport = req_udp->uh_sport; // copied from source port of corresponding Registration Request
        uint16_t len = packet->length() - sizeof(click_ip);
        udp_head->uh_ulen = htons(len);

        // add mobile IP fields
        registration_reply_header *rep_head = (registration_reply_header*)(udp_head + 1);

        rep_head->type = 3; // Registration Reply
        rep_head->code = code;
        rep_head->lifetime = req_rh->lifetime;
        rep_head->home_addr = req_rh->home_addr;
        rep_head->id = req_rh->id;
        rep_head->home_agent = req_rh->home_agent;

        // Calculate the udp checksum
        udp_head->uh_sum = click_in_cksum_pseudohdr(click_in_cksum((unsigned char*)udp_head, packet_size - sizeof(click_ip)), ip_head, packet_size - sizeof(click_ip));

        // send reply either to eth0 or to eth1
        if (req_rh->home_addr == req_rh->co_addr)
            output(0).push(packet);
        else
            output(1).push(packet);
    }

    p->kill();
}

uint8_t RegistrationReplier::check_acceptability(Packet *packet) {
    click_ip *req_ip = (click_ip*)packet->data();
    click_udp *req_udp = (click_udp*)(req_ip + 1);
    registration_request_header *req_rh = (registration_request_header*)(req_udp + 1);

    // if r or x flags in request not 0, return 'Poorly formed request' code (134)
    uint8_t flags = req_rh->flags;
    if((flags & 1) || ((flags >> 2) & 1)) {
        return 134;
    }

    // if D bit set, return Reply denying Request with 'Reason unspecified' code (),
    // since this implementation does not support co-located Care-of-Addresses
    if((flags >> 5) & 1) {
    	return 128;
    }

    // if S bit set and already bound, return 'Too many simultaneous mobility bindings' code (135)
    // check if mobile node requesting registration is already registered
    bool already_bound = false;
    for (Vector<MobileNodeInfo>::iterator it = _infobase->mobileNodesInfo.begin();
    		it != _infobase->mobileNodesInfo.end(); ++it) {
    	if(it->address == req_rh->home_addr) {
    		already_bound = true;
    		break;
    	}
    }
    if(((flags >> 7) & 1) && already_bound) {
    	return 135;
    }

    // if HomeAgent field in request is not unicast, return 'Unknown home agent address' code (136)
    if (req_rh->home_agent == _allMobileAgentsAddress.addr()) {
    	return 136;
    }

    // if something else is wrong, return 'Reason unspecified' code //TODO when?

    return 1; // If request is accepted, return code 1, since simultaneous bindings are not supported
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RegistrationReplier)
