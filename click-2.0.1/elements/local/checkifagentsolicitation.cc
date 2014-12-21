#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include "checkifagentsolicitation.hh"
#include "agentsolicitation.hh"

CLICK_DECLS
CheckIfAgentSolicitation::CheckIfAgentSolicitation()
{}

CheckIfAgentSolicitation::~CheckIfAgentSolicitation()
{}

int CheckIfAgentSolicitation::configure(Vector<String> &conf, ErrorHandler *errh) {

    if (cp_va_kparse(conf, this, errh, cpEnd) < 0)
        return -1;

    return 0;
}

void CheckIfAgentSolicitation::push(int, Packet* packet) {

    click_ether* ethh = (click_ether*)packet->data();

    click_ip* iph = (click_ip*)(ethh + 1);
    if (iph->ip_p == 1) // ICMP packet
    {
        agent_solicitation_header* ash = (agent_solicitation_header*)(iph + 1);
        if (ash->type == 10) // Agent Solicitation
        {
            // Silently discard packet if source address is 0
            if (iph->ip_src == 0) {
                packet->kill();
                return;
            }

            // Silently discard packet if ICMP Checksum is invalid
            if (click_in_cksum((unsigned char*)ash, sizeof(agent_solicitation_header)) != 0) {
                packet->kill();
                return;
            }

            // Silently discard packet if ICMP Code is not 0
            if (ash->code != 0) {
                packet->kill();
                return;
            }

            // Silently discard packet if ICMP length (derived from the IP length) is not 8 or more octets
            if (ntohs(iph->ip_len) >= 8 + sizeof(click_ip)) {
                packet->kill();
                return;
            }

            output(0).push(packet);
            return;
        }
    }

    // Not an agent solicitation
    output(1).push(packet);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(CheckIfAgentSolicitation)
