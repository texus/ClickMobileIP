#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/udp.h>
#include "registrationreplier.hh"
#include "registernode.hh"

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
}

CLICK_DECLS

RegisterNode::RegisterNode() :_timer(this) {}

RegisterNode::~RegisterNode() {}

int RegisterNode::configure(Vector<String> &conf, ErrorHandler *errh) {

    bool almostExpiredLifetimeGiven;
    if(cp_va_kparse(conf, this, errh,
                    "INFOBASE", cpkP + cpkM, cpElement, &_infobase,
                    "ALMOST_EXPIRED_LIFETIME", cpkC, &almostExpiredLifetimeGiven, cpUnsigned, &_almostExpiredLifetime,
                    cpEnd) < 0) return -1;

    if (!almostExpiredLifetimeGiven)
        _almostExpiredLifetime = 3;

    _timer.initialize(this);
    return 0;
}

void RegisterNode::push(int, Packet *p) {
    // receive reply
    click_ip *ip_h = (click_ip *)p->data();
    click_udp *udp_h = (click_udp *)(ip_h + 1);
    registration_reply_header *rep_h = (registration_reply_header *)(udp_h + 1);

    // get corresponding pending request
    Vector<pending_request>::iterator most_recent;
    bool corresponding_found = false;
    for(Vector<pending_request>::iterator it = _infobase->pending.begin();it != _infobase->pending.end(); ++it) {
        if(it->ip_dst == ip_h->ip_src && it->src_port == ntohs(udp_h->uh_dport)) {
            corresponding_found = true;
            most_recent = it;
            break;
        }
    }

    if(!corresponding_found) {
        p->kill();
        return;
     }

    // If the UDP checksum is wrong then discard the packet silently.
    // The checksum is still part of the packet, which is why we check for not null, instead of checking whether what we calculate equals the checksum.
    if ((click_in_cksum_pseudohdr(click_in_cksum((unsigned char*)udp_h, p->length() - sizeof(click_ip)), ip_h, p->length() - sizeof(click_ip)) != 0) 
     && (ntohs(udp_h->uh_sum) != 0))
    {
        p->kill();
        // remove pending request
        _infobase->pending.erase(most_recent);
        return;
    }

    // compare ID of reply to ID of most recent request sent to replying agent
    // if not matching, discard silently
    int id1 = rep_h->id;
    int id2 = most_recent->id;
    if(ntohll(rep_h->id) != most_recent->id) {
        p->kill();
        return;
    }

    // check if accepted
    uint8_t code = rep_h->code;
    if(code == 0 || code == 1) {
        _timer.clear();

        // request accepted, adapt mobile node infobase
        if(ip_h->ip_src != _infobase->homeAgent) {
            // registering on foreign network
            _infobase->connected = true;
            _infobase->foreignAgent = IPAddress(most_recent->ip_dst);
            // set lifetime
            uint16_t granted_lifetime = ntohs(rep_h->lifetime);
            uint16_t requested_lifetime = most_recent->requested_lifetime;
            uint16_t decreased = requested_lifetime - granted_lifetime;
            uint16_t lifetime = most_recent->remaining_lifetime - decreased;
            _infobase->lifetime = lifetime;

            _timer.schedule_after_sec(1);
        }
        else {
            _infobase->connected = true;
        }

        // remove pending request
        _infobase->pending.erase(most_recent);
    }
    else {
        // act according to reply code
        // log error
        String message = "Request denied: ";
        switch(code) {
            case 64: case 128:
                message += "reason unspecified";
                break;
            case 70: case 134:
                message += "poorly formed Request";
                break;
            case 71:
                message += "poorly formed Reply";
                break;
            case 72:
                message += "requested encapsulation unavailable";
                break;
            case 80:
                message += "home network unreachable (ICMP error received)";
                break;
            case 135:
                message += "too many simultaneous mobility bindings";
                break;
            case 136:
                message += "unknown home agent address";
                break;
            default:
                message += "unknown exception code";
                break;
        }
        click_chatter(message.data());

        // remove pending request
        _infobase->pending.erase(most_recent);
    }

    p->kill();
}

void RegisterNode::run_timer(Timer* timer)
{
    // Decrease the registration lifetime
    if (_infobase->lifetime > 0)
    {
        _infobase->lifetime--;

        if (_infobase->lifetime == _almostExpiredLifetime)
        {
            // when registration almost expired, look for advertisement of current foreign agent
            // & relay to element that sends requests
            Packet *p = _infobase->advertisements[_infobase->foreignAgent];
            if(p != 0)
                output(0).push(p->clone());
        }
        if (_infobase->lifetime == 0)
        {
            _infobase->connected = false;
        }
    }

    _timer.schedule_after_sec(1);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RegisterNode);
