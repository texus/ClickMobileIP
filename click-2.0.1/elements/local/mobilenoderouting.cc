#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "mobilenoderouting.hh"

CLICK_DECLS
MobileNodeRouting::MobileNodeRouting()
{}

MobileNodeRouting::~MobileNodeRouting()
{}

int MobileNodeRouting::configure(Vector<String> &conf, ErrorHandler *errh) {

    if (cp_va_kparse(conf, this, errh,
                     "INFOBASE", cpkP + cpkM, cpElement, &_infobase,
                     cpEnd) < 0)
        return -1;

    return 0;
}

void MobileNodeRouting::push(int, Packet* packet) {

    // Send the package to the correct location
    if (_infobase->connected)
        packet->set_dst_ip_anno(htonl(_infobase->foreignAgent));

    output(0).push(packet);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MobileNodeRouting)
