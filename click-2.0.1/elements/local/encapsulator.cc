#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include "encapsulator.hh"

CLICK_DECLS
Encapsulator::Encapsulator()
{}

Encapsulator::~Encapsulator()
{}

int Encapsulator::configure(Vector<String> &conf, ErrorHandler *errh) {

    if (cp_va_kparse(conf, this, errh,
                     "SRC_IP", cpkM, cpIPAddress, &_srcIp,
                     "DST_IP", cpkM, cpIPAddress, &_dstIp,
                     cpEnd) < 0)
        return -1;

    return 0;
}

void Encapsulator::push(int, Packet* innerPacket) {

    int packetsize = innerPacket->length();
    int headroom = sizeof(click_ip) + sizeof(click_ether);
    WritablePacket* packet = Packet::make(headroom, 0, packetsize, 0);
    if (packet == 0)
    {
        click_chatter("cannot make packet!");
        return;
    }

    // Copy the contents of the packet into the one that will be send
    memcpy(packet->data(), innerPacket->data(), innerPacket->length());

    // Push the outer ip header around the packet
    packet = packet->push(sizeof(click_ip));
    if (packet == 0)
    {
        click_chatter("cannot make packet!");
        return;
    }

    memset(packet->data(), 0, sizeof(click_ip));

    click_ip* inneriph = (click_ip*)innerPacket->data();
    click_ip* iph = (click_ip*)packet->data();
    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_tos = inneriph->ip_tos;
    iph->ip_len = htons(sizeof(click_ip) + ntohs(inneriph->ip_len));
    iph->ip_id = htons(0); /// TODO: What value should go here?
    iph->ip_ttl = 200;
    iph->ip_p = 4; // protocol = IP-in-IP
    iph->ip_src.s_addr = _srcIp; // ip address of encapsulator
    iph->ip_dst.s_addr = _dstIp; // ip address of decapsulator
    iph->ip_sum = click_in_cksum((unsigned char*)packet->data(), packet->length());

    packet->set_dst_ip_anno(iph->ip_dst);

    output(0).push(packet);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Encapsulator)
