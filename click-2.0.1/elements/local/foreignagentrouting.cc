#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "foreignagentrouting.hh"

CLICK_DECLS
ForeignAgentRouting::ForeignAgentRouting()
{}

ForeignAgentRouting::~ForeignAgentRouting()
{}

int ForeignAgentRouting::configure(Vector<String> &conf, ErrorHandler *errh) {

    if (cp_va_kparse(conf, this, errh,
                     "INFOBASE", cpkP + cpkM, cpElement, &_infobase,
                     cpEnd) < 0)
        return -1;

    return 0;
}

void ForeignAgentRouting::push(int, Packet* packet) {

    click_ip* iph = (click_ip*)packet->data();

    //if (_infobase->current_registrations.find_pair(iph->ip_dst) != 0)
    if (_infobase->current_registrations.size() > 0)
    {

    }

    output(0).push(packet);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ForeignAgentRouting)
