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
{
    // TODO: REMOVE THIS WHEN REGISTRATION IS IMPLEMENTED
    //       This code hardcodes the mobile nodes location as the foreign agent
    MobileNodeInfo info;
    info.address = inet_addr("192.168.2.1");
    info.careOfAddress = inet_addr("192.168.1.3");
    mobileNodesInfo.push_back(info);
}

HomeAgentInfobase::~HomeAgentInfobase()
{}

int HomeAgentInfobase::configure(Vector<String> &conf, ErrorHandler *errh) {

    if (cp_va_kparse(conf, this, errh, cpEnd) < 0)
        return -1;

    return 0;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(HomeAgentInfobase)
