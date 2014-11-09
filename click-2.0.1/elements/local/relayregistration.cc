#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/udp.h>
#include "relayregistration.hh"
#include "registrationrequester.hh"
#include "registrationreplier.hh"

CLICK_DECLS

RelayRegistration::RelayRegistration(): _timer(this) {}

RelayRegistration::~RelayRegistration() {}

int RelayRegistration::configure(Vector<String> &conf, ErrorHandler *errh) {
    if(cp_va_kparse(conf, this, errh, "INFOBASE", cpkP + cpkM, cpElement, &_infobase, cpEnd) < 0) return -1;

    _timer.initialize(this);
    _timer.schedule_after_msec(1000);
    return 0;
}

void RelayRegistration::push(int, Packet *p) {
    click_ip *ip_h = (click_ip *)p->data();
    click_udp *udp_h = (click_udp *)(ip_h + 1);
    uint32_t packet_size = p->length();
    if(packet_size == sizeof(click_ip) + sizeof(click_udp) + sizeof(registration_request_header)) {
        registration_request_header *req_h = (registration_request_header*)(udp_h + 1);
        if(req_h->type == 1) {
            // relaying registration request
            click_chatter("Relaying registration request");
            // check if home address does not belong to network interface of foreign agent //TODO
            // if acting as home agent, send packet to registration replier //TODO
            // else, reject using code 136

            // if home address not in network 
            // if non-zero UDP, discard silently
            uint8_t flags = req_h->flags;
            if(flags != 0 || (flags >> 2) != 0) {
                // if non-zero flags in zero-bits of request, reject with code 70 (poorly formed request)
                // TODO send reply message
            }

            // + add information to visitor table //TODO
            // link-layer source address of mobile node
            // IP Source Address (= mobile node Home Address)
            // IP Destination Address
            // UDP Source Port
            // Home Agent Address
            // Identification field
            // requested registration Lifetime
            // remaining Lifetime of pending or current registration

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
            //ip_head->ip_sum = click_in_cksum((unsigned char*)ip_head, htons(packet_size)); //TODO calculate in element?

            // set annotation
            packet->set_dst_ip_anno(ip_head->ip_dst);

            // set UDP fields
            udp_head->uh_sport = htons(434);
            udp_head->uh_dport = udp_h->uh_sport; 
            udp_head->uh_sum = 0;

            //relay to home agent 
            output(0).push(packet);
        }
        else { 
            click_chatter("relaying registration reply (faulty)");     
        }
        
    }

    else if(packet_size = sizeof(click_ip) + sizeof(click_udp) + sizeof(registration_reply_header) + sizeof(uint64_t)) {
        registration_reply_header *rep_h = (registration_reply_header*)(udp_h + 1);
        if(rep_h->type == 3) {
            // relaying registration reply
            click_chatter("Relaying registration reply");

            // if UDP checksum not 0, discard silently
 
            // if no pending request with same home address as home address in reply, discard silently

            // if ids not equal, discard silently

            // update visitor list
            // if accepted -> set current
            // if accepted & lifetime = 0 -> remove from visitor list

            // if denied: remove pending request entry

            // relay to mobile node
            
        }
    }


    /*
    * Registration denied by foreign agent
    *   64      reason unspecified
    *   ...
    *   (66      insufficient resources (if max number of pending registrations exceeded))
    *   ...
    *   70      poorly formed Request
    *   71      poorly formed Reply
    *   72      requested encapsulation unavailable
    *   ...
    *   (78      registration timeout)
    *   ...
    *   80      home network unreachable (ICMP error received)
    *   ...
    */
}

void RelayRegistration::run_timer(Timer *timer) {
    // lower remaining lifetime of pending requests
    for(Vector<visitor_entry>::iterator it = _infobase->pending_requests.begin(); it != _infobase->pending_requests.end(); ++it) {
        if(it->remaining_lifetime > 1) {
            --(it->remaining_lifetime);
            if(it->requested_lifetime - it->remaining_lifetime > 7) {
                // if request is pending for longer than 7 seconds, send timeout reply + delete from list //TODO                
            }
        }
        else {
            // remove pending request //TODO
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

CLICK_ENDDECLS
EXPORT_ELEMENT(RelayRegistration)
