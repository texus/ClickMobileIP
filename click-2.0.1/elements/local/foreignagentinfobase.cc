#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "foreignagentinfobase.hh"

CLICK_DECLS

ForeignAgentInfobase::ForeignAgentInfobase()
{}

ForeignAgentInfobase::~ForeignAgentInfobase() 
{}

int ForeignAgentInfobase::configure(Vector<String>&, ErrorHandler*) {
    return 0;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ForeignAgentInfobase)
