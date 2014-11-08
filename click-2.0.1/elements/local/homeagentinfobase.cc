#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "homeagentinfobase.hh"

CLICK_DECLS
HomeAgentInfobase::HomeAgentInfobase()
{}

HomeAgentInfobase::~HomeAgentInfobase()
{}

int HomeAgentInfobase::configure(Vector<String> &conf, ErrorHandler *errh) {

    if (cp_va_kparse(conf, this, errh, cpEnd) < 0)
        return -1;

    return 0;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(HomeAgentInfobase)
