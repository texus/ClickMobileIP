#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include "checkifencapsulated.hh"

CLICK_DECLS
CheckIfEncapsulated::CheckIfEncapsulated()
{}

CheckIfEncapsulated::~CheckIfEncapsulated()
{}

int CheckIfEncapsulated::configure(Vector<String> &conf, ErrorHandler *errh) {

    if (cp_va_kparse(conf, this, errh, cpEnd) < 0)
        return -1;

    return 0;
}

void CheckIfEncapsulated::push(int, Packet* packet) {

    // Encapsulated packages are send to output 0, normal packages to output 1
    click_ip* iph = (click_ip*)packet->data();
    if (iph->ip_p == 4)
        output(0).push(packet);
    else
        output(1).push(packet);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(CheckIfEncapsulated)
