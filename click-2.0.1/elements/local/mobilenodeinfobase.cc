#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "mobilenodeinfobase.hh"

CLICK_DECLS
MobileNodeInfobase::MobileNodeInfobase() : connected(false)
{}

MobileNodeInfobase::~MobileNodeInfobase()
{}

int MobileNodeInfobase::configure(Vector<String> &conf, ErrorHandler *errh) {

    if (cp_va_kparse(conf, this, errh,
                     "HOME_AGENT", cpkP + cpkM, cpIPAddress, &homeAgent,
                     "HOME_ADDRESS", cpkP + cpkM, cpIPAddress, &homeAddress,
                     cpEnd) < 0)
        return -1;

    foreignAgent = IPAddress(0);
    return 0;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MobileNodeInfobase)
