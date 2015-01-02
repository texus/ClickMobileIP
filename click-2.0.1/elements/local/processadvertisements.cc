#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include "processadvertisements.hh"
#include "mobilityagentadvertiser.hh"

CLICK_DECLS
ProcessAdvertisements::ProcessAdvertisements()
{}

ProcessAdvertisements::~ProcessAdvertisements()
{
    for (HashMap<IPAddress, Packet*>::iterator it = _infobase->advertisements.begin(); it != _infobase->advertisements.end(); ++it)
        it.pair()->value->kill();
}

int ProcessAdvertisements::configure(Vector<String> &conf, ErrorHandler *errh) {

    if (cp_va_kparse(conf, this, errh,
                     "INFOBASE", cpkP + cpkM, cpElement, &_infobase,
                     cpEnd) < 0)
        return -1;

    return 0;
}

void ProcessAdvertisements::push(int, Packet* packet)
{
    click_ip* iph = (click_ip*)packet->data();
    if (iph->ip_p == 1) // ICMP packet
    {
        advertisement_header* advh = (advertisement_header*)(iph + 1);
        if (advh->type == 9) // Router Advertisement
        {
        	uint16_t last_seq_nr = -1;
            mobile_advertisement_header* madvh = (mobile_advertisement_header*)(advh + 1);
            if (madvh->type == 16)
            {
                HashMap<IPAddress, Packet*>::Pair* p = _infobase->advertisements.find_pair(advh->address);
                if (p != 0)
                {
                    click_ip *ip_head = (click_ip *)p->value->data();
                    advertisement_header *adv_head = (advertisement_header*)(ip_head + 1);
                    mobile_advertisement_header *madv_head = (mobile_advertisement_header*)(adv_head + 1);
                    last_seq_nr = madv_head->seq_nr;
                    for (Vector<Pair<IPAddress, Timer> >::iterator it = _timers.begin(); it != _timers.end(); ++it)
                    {
                        if (it->first == p->key)
                        {
                            _timers.erase(it);
                            break;
                        }
                    }

                    p->value->kill();
                    _infobase->advertisements.erase(advh->address);
                }

                // Ignore the message when the busy bit was set
                if (((madvh->flags >> 6) & 1) == 0)
                {
                    // If there is no connection yet then try to connect to this agent
                    if (!_infobase->connected)
                    {
                        _infobase->advertisements.insert(advh->address, packet->clone());

                        _lastRegistrationAttempt.assign_now();
                        output(1).push(packet);
                    }
                    // If sequence number resets (without rollover), re-register with FA
                    else if (madvh->seq_nr <= last_seq_nr && madvh->seq_nr < 256) {
                        _infobase->advertisements.insert(advh->address, packet->clone());

                        _lastRegistrationAttempt.assign_now();
                        output(1).push(packet);
                    }
                    else {
                        _infobase->advertisements.insert(advh->address, packet);
                    }

                    _timers.push_back(Pair<IPAddress, Timer>(advh->address, Timer(this)));
                    _timers.back().second.initialize(this);
                    _timers.back().second.schedule_after_msec(1000);
                }

                return;
            }
        }
    }

    output(0).push(packet);
}

void ProcessAdvertisements::run_timer(Timer* timer)
{
    IPAddress address;
    Packet* packet;
    for (Vector<Pair<IPAddress, Timer> >::iterator it = _timers.begin(); it != _timers.end(); ++it)
    {
        if (&it->second == timer)
        {
            HashMap<IPAddress, Packet*>::Pair* p = _infobase->advertisements.find_pair(it->first);
            if (p == 0)
            {
                click_chatter("Failed to find advertisement for which timer expired");
                return;
            }

            address = p->key;
            packet = p->value;
            break;
        }
    }

    click_ip* iph = (click_ip*)packet->data();
    advertisement_header* advh = (advertisement_header*)(iph + 1);
    uint16_t lifetime = ntohs(advh->lifetime);

    bool connectedAgentUnavailable = !_infobase->connected;
    if (lifetime > 0)
    {
        lifetime--;
        advh->lifetime = htons(lifetime);

        timer->schedule_after_msec(1000);
    }
    else // Lifetime expired
    {
        if ((_infobase->connected) && (_infobase->foreignAgent == address))
            connectedAgentUnavailable = true;

        HashMap<IPAddress, Packet*>::Pair* p = _infobase->advertisements.find_pair(address);
        if (p == 0)
        {
            click_chatter("Advertisement package that is to be removed could not be found.");
            return;
        }
        p->value->kill();
        _infobase->advertisements.erase(address);
        _infobase->connected = false;

        for (Vector<Pair<IPAddress, Timer> >::iterator it = _timers.begin(); it != _timers.end(); ++it)
        {
            if (&it->second == timer)
            {
                _timers.erase(it);
                break;
            }
        }
    }

    // Try to connect with another agent when no longer receiving advertisements from currently connected one
    if (connectedAgentUnavailable)
    {
        if ((!_infobase->advertisements.empty()) && (_lastRegistrationAttempt + Timestamp::make_sec(1) < Timestamp::now()))
        {
            _lastRegistrationAttempt.assign_now();

            // Just connect to the first router advertisement that we still have in the cache
            output(1).push(_infobase->advertisements.begin().pair()->value->clone());
        }
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ProcessAdvertisements)
