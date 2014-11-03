#include <time.h>
#include <stdlib.h>
#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include "agentsolicitation.hh"

CLICK_DECLS
AgentSolicitation::AgentSolicitation() : _timer(this), _messagesSendInRow(0)
{
}

AgentSolicitation::~AgentSolicitation()
{}

int AgentSolicitation::configure(Vector<String> &conf, ErrorHandler *errh) {

    if (cp_va_kparse(conf, this, errh,
                     "INFOBASE", cpkP + cpkM, cpElement, &_infobase,
                     "SRC_IP", cpkM, cpIPAddress, &_srcIp,
                     cpEnd) < 0)
        return -1;

    _timer.initialize(this);
    _timer.schedule_after_msec(10); // Let the mobile node send a solicitation message when it starts
    return 0;
}

void AgentSolicitation::run_timer(Timer* timer)
{
    // Don't do anything when it isn't needed yet
    if (_infobase->connected || !_infobase->advertisements.empty())
    {
        _messagesSendInRow = 0;
        timer->schedule_after_msec(1000);
        return;
    }

    // If no router responds after a number of messages than stop sending messages
    // TODO: Make the amount configurable
    if (_messagesSendInRow >= 5)
    {
        timer->schedule_after_msec(1000);
        return;
    }

    _messagesSendInRow++;

    int packetsize = sizeof(click_ip) + sizeof(agent_solicitation_header);
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
    iph->ip_id = 0; // TODO: Do we need an id?
    iph->ip_ttl = 1; // TTL must be 1 in solicitation
    iph->ip_p = 1; // protocol = ICMP
    iph->ip_src = _srcIp;
    iph->ip_dst.s_addr = 0xffffffff;

    packet->set_dst_ip_anno(iph->ip_dst);

    agent_solicitation_header* ash = (agent_solicitation_header*)(iph + 1);
    ash->type = 10; // Agent solicitation
    ash->code = 0;

    // Calculate the header checksums
    iph->ip_sum = click_in_cksum((unsigned char*)packet->data(), sizeof(click_ip));
    ash->checksum = click_in_cksum((unsigned char*)ash, packetsize - sizeof(click_ip));

    output(0).push(packet);

    timer->schedule_after_msec(1000);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(AgentSolicitation)
