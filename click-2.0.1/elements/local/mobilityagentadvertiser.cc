#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include "mobilityagentadvertiser.hh"

/* most icmp request types: ICMP_UNREACH, ICMP_SOURCEQUENCH, ICMP_TIMXCEED */
struct advertisement_header {
    uint8_t     type;		    /* 0    Type = 16 */
    uint8_t     length;         /* 1    Lenght = 6 + 4*N (with N number of care-of addresses) */
    uint16_t    seq_nr;	        /* 2-3  Sequence Number */
    uint16_t	lifetime;       /* 4-5   Registration lifetime */
    uint8_t	    flags;		    /* 6    Flags */
    uint8_t     reserved;       /* 7    should be zero */
};

CLICK_DECLS
MobilityAgentAdvertiser::MobilityAgentAdvertiser()
	: _interval(0), _timer(this)
{}

MobilityAgentAdvertiser::~MobilityAgentAdvertiser()
{}

int MobilityAgentAdvertiser::configure(Vector<String> &conf, ErrorHandler *errh) {

	if (cp_va_kparse(conf, this, errh, 
	            "SRC_IP", cpkM, cpIPAddress, &_srcIp,
				"INTERVAL", cpkM, cpUnsigned, &_interval,
				cpEnd) < 0) 
		return -1;
	
	_timer.initialize(this);
	_timer.schedule_after_msec(_interval*1000);
		
	return 0;
}

void MobilityAgentAdvertiser::run_timer(Timer *) {

    int packetsize = sizeof(click_ip) + sizeof(advertisement_header);
    int headroom = sizeof(click_ether);
    WritablePacket* packet = Packet::make(headroom, 0, packetsize, 0);
    if (packet == 0)
    {
        click_chatter("cannot make packet!");
        return;
    }

    memset(packet->data(), 0, packet->length());
    _sequenceNr++;
    
    click_ip* iph = (click_ip*)packet->data();
    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_tos = 0;
    iph->ip_len = htons(28);
    iph->ip_id = htons(_sequenceNr);
    iph->ip_ttl = 200;
    iph->ip_p = 1;
    iph->ip_src = _srcIp; // TODO: Is htons needed here?
    iph->ip_dst.s_addr = 0xffffffff;
    iph->ip_sum = click_in_cksum((unsigned char*)packet->data(), packet->length()); // TODO: Is htons needed here?
    
    packet->set_dst_ip_anno(iph->ip_dst);

    advertisement_header* advh = (advertisement_header*)(iph + 1);
    advh->type = 16;
    advh->length = 6 + 4 * 0; // TODO: Change 0 to number of care-of addresses
    advh->seq_nr = htons(_sequenceNr);
    advh->lifetime = htons(0xffff); // TODO: Set to non-infinite lifetime
    advh->flags = 0; // TODO: Set flags

    output(0).push(packet);
	_timer.schedule_after_msec(_interval*1000);
}

void MobilityAgentAdvertiser::push(int input, Packet *p){
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MobilityAgentAdvertiser)
