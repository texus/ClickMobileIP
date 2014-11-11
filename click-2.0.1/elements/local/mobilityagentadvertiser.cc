#include <time.h>
#include <stdlib.h>
#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include "mobilityagentadvertiser.hh"

CLICK_DECLS
MobilityAgentAdvertiser::MobilityAgentAdvertiser()
    : _interval(0), _timer(this), _sequenceNr(0)
{
    srand(time(NULL));
}

MobilityAgentAdvertiser::~MobilityAgentAdvertiser()
{}

int MobilityAgentAdvertiser::configure(Vector<String> &conf, ErrorHandler *errh) {

    bool intervalGiven;
    bool lifetimeGiven;
    if (cp_va_kparse(conf, this, errh,
                     "SRC_IP", cpkM, cpIPAddress, &_srcIp,
                     "CARE_OF_ADDRESS", cpkM, cpIPAddress, &_careOfAddress,
                     "HOME_AGENT", cpkM, cpBool, &_homeAgent,
                     "FOREIGN_AGENT", cpkM, cpBool, &_foreignAgent,
                     "INTERVAL", cpkC, &intervalGiven, cpUnsigned, &_interval,
                     "LIFETIME", cpkC, &lifetimeGiven, cpUnsigned, &_lifetime,
                     cpEnd) < 0)
        return -1;

    if (!_homeAgent && !_foreignAgent)
    {
        errh->error("Either home agent or foreign agent option has to be set!");
        return -1;
    }

    if (!lifetimeGiven)
        _lifetime = 0xffff;

    if (intervalGiven)
    {
        _timer.initialize(this);
        _timer.schedule_after_msec(_interval);
    }

    return 0;
}

void MobilityAgentAdvertiser::push(int, Packet* packet)
{
    click_ether* ethh = (click_ether*)packet->data();
    click_ip* iph = (click_ip*)(ethh + 1);

    sendPacket(iph->ip_src);
}

void MobilityAgentAdvertiser::run_timer(Timer *)
{
    sendPacket(IPAddress::make_broadcast());

    int rnd = (rand() % 200) - 100;
    _timer.schedule_after_msec(_interval + rnd);
}

void MobilityAgentAdvertiser::sendPacket(IPAddress destinationIP)
{
    int packetsize = sizeof(click_ip) + sizeof(advertisement_header) + sizeof(mobile_advertisement_header);
    int headroom = sizeof(click_ether);
    WritablePacket* packet = Packet::make(headroom, 0, packetsize, 0);
    if (packet == 0)
    {
        click_chatter("cannot make packet!");
        return;
    }

    memset(packet->data(), 0, packet->length());

    click_ip* iph = (click_ip*)packet->data();
    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_tos = 0;
    iph->ip_len = htons(packetsize);
    iph->ip_id = htons(_sequenceNr);
    iph->ip_ttl = 1; // TTL must be 1 in advertisement
    iph->ip_p = 1; // protocol = ICMP
    iph->ip_src = _srcIp;
    iph->ip_dst = destinationIP;
    iph->ip_sum = click_in_cksum((unsigned char*)packet->data(), packet->length());

    packet->set_dst_ip_anno(iph->ip_dst);

    advertisement_header* advh = (advertisement_header*)(iph + 1);
    advh->type = 9; // Router Advertisement
    advh->code = 0; // Also handles normal routing
    advh->addresses = 1;
    advh->addr_size = 2;
    advh->lifetime = htons(2); // TODO: Allow changing lifetime
    advh->address = _srcIp;
    advh->addrPreference = 0;

    mobile_advertisement_header* madvh = (mobile_advertisement_header*)(advh + 1);
    madvh->type = 16;
    madvh->length = 6 + 4 * 1;
    madvh->seq_nr = htons(_sequenceNr);
    madvh->lifetime = htons(_lifetime);
    madvh->address = _careOfAddress;
    madvh->flags =  (1 << 7) // Registration required
                  + (0 << 6) // Busy
                  + (_homeAgent << 5) // Home agent
                  + (_foreignAgent << 4) // Foreign agent
                  + (0 << 3) // Minimal encapsulation  ///TODO: Check correct value
                  + (0 << 2) // GRE encapsulation  ///TODO: Check correct value
                  + (0 << 1) // ignore
                  + 0;       // Foreign agent supports reverse tunneling  ///TODO: Check correct value

    // Calculate the ICMP header checksum
    advh->checksum = click_in_cksum((unsigned char*)advh, packetsize - sizeof(click_ip));

    // Increment the sequence number
    if (_sequenceNr < 0xffff)
        _sequenceNr++;
    else
        _sequenceNr = 256;

    output(0).push(packet);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MobilityAgentAdvertiser)
