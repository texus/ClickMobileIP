#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "foreignagentinfobase.hh"

CLICK_DECLS

ForeignAgentInfobase::ForeignAgentInfobase()
{}

ForeignAgentInfobase::~ForeignAgentInfobase() 
{}

int ForeignAgentInfobase::configure(Vector<String>& conf, ErrorHandler *errh) {
    if(cp_va_kparse(conf, this, errh, "ADDRESS", cpkP + cpkM, cpIPAddress, &address, cpEnd) < 0) return -1;
    return 0;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ForeignAgentInfobase)
