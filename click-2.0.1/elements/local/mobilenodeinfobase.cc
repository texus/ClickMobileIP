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

    // Foreign agent is set to home agent to indicate that the mobile node is not on a foreign agent
    foreignAgent = homeAgent;

    // TODO: REMOVE THIS WHEN NO LONGER HARDCODING MOBILE NODE POSITION
    //connected = true;
    //foreignAgent = 0xC0A803FE;
    //lifetime = 500;

    return 0;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MobileNodeInfobase)
