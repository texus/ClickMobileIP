#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include "processadvertisements.hh"
#include "mobilityagentadvertiser.hh"

CLICK_DECLS
ProcessAdvertisements::ProcessAdvertisements() : _timer(this)
{}

ProcessAdvertisements::~ProcessAdvertisements()
{}

int ProcessAdvertisements::configure(Vector<String> &conf, ErrorHandler *errh) {

    if (cp_va_kparse(conf, this, errh,
                     "INFOBASE", cpkP + cpkM, cpElement, &_infobase,
                     cpEnd) < 0)
        return -1;

    _timer.initialize(this);
    _timer.schedule_after_msec(1000);
    return 0;
}

void ProcessAdvertisements::push(int, Packet* packet) {

    StringAccum sa(packet->length());
    for (unsigned int i = 0; i < packet->length(); ++i)
        sa << packet->data()[i];

    click_ip* iph = (click_ip*)packet->data();
    if (iph->ip_p == 1) // ICMP packet
    {
        advertisement_header* advh = (advertisement_header*)(iph + 1);
        if (advh->type == 9) // Router Advertisement
        {
            mobile_advertisement_header* madvh = (mobile_advertisement_header*)(advh + 1);
            if (madvh->type == 16)
            {
                _infobase->advertisementLifetimeInfo.insert(madvh->address, ntohs(advh->lifetime));
                output(1).push(packet);
                return;
            }
        }
    }

    output(0).push(packet);
}

void ProcessAdvertisements::run_timer(Timer* timer){

    // Decrease the registration lifetime
    if (_infobase->lifetime > 0)
    {
        _infobase->lifetime--;

        if (_infobase->lifetime == 0)
        {
            /// TODO: Should we do something here?
            ///       Our registration is no longer valid.
        }
    }

    // Decrease the lifetime of the stored advertisement messages
    Vector<IPAddress> elementToBeRemoved;
    for (HashMap<IPAddress, uint16_t>::iterator it = _infobase->advertisementLifetimeInfo.begin(); it != _infobase->advertisementLifetimeInfo.end(); ++it)
    {
        click_chatter("%d", it.pair()->value);

        if (it.pair()->value > 1)
            it.pair()->value--;
        else // Lifetime expired
            elementToBeRemoved.push_back(it.pair()->key);
    }

    // Remove the advertisement messages of which the lifetime has reached 0
    for (Vector<IPAddress>::const_iterator it = elementToBeRemoved.begin(); it != elementToBeRemoved.end(); ++it)
        _infobase->advertisementLifetimeInfo.erase(*it);

    timer->schedule_after_msec(1000);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ProcessAdvertisements)
