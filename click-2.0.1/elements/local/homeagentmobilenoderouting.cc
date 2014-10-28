#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include "homeagentmobilenoderouting.hh"

CLICK_DECLS
HomeAgentMobileNodeRouting::HomeAgentMobileNodeRouting()
{}

HomeAgentMobileNodeRouting::~HomeAgentMobileNodeRouting()
{}

int HomeAgentMobileNodeRouting::configure(Vector<String> &conf, ErrorHandler *errh) {

    if (cp_va_kparse(conf, this, errh,
                     "INFOBASE", cpkP + cpkM, cpElement, &_infobase,
                     cpEnd) < 0)
        return -1;

    return 0;
}

void HomeAgentMobileNodeRouting::push(int, Packet* packet) {

    for (unsigned int i = 0; i < _infobase->mobileNodesInfo.size(); ++i)
    {
        if (_infobase->mobileNodesInfo[i].address == ((click_ip*)packet->data())->ip_dst)
        {
            output(1).push(packet);
            return;
        }
    }

    output(0).push(packet);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(HomeAgentMobileNodeRouting)
