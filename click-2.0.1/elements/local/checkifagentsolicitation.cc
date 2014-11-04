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
        agent_solicitation_header* advh = (agent_solicitation_header*)(iph + 1);
        if (advh->type == 10) // Agent Solicitation
        {
            output(0).push(packet);
            return;
        }
    }

    // Not an agent solicitation
    output(1).push(packet);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(CheckIfAgentSolicitation)
