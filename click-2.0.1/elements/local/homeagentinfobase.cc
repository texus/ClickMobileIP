#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "homeagentinfobase.hh"

// TODO: REMOVE THESE INCLUDES TOGETHER WITH CODE IN CONSTRUCTOR
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
