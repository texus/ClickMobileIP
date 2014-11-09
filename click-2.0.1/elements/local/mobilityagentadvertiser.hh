#ifndef CLICK_MOBILITYAGENTADVERTISER_HH
#define CLICK_MOBILITYAGENTADVERTISER_HH
#include <click/element.hh>
#include <click/timer.hh>

CLICK_DECLS

class MobilityAgentAdvertiser : public Element {
	public:
		MobilityAgentAdvertiser();
		~MobilityAgentAdvertiser();

		const char *class_name() const	{ return "MobilityAgentAdvertiser"; }
		const char *port_count() const 	{ return "0-1/1"; }
		const char *processing() const	{ return PUSH; }

		int configure(Vector<String>&, ErrorHandler*);

		void push(int, Packet*);
		void run_timer(Timer *);

	private:
	    void sendPacket(IPAddress destinationIP);

	private:
	    IPAddress _srcIp;
	    IPAddress _careOfAddress;

		int _interval;
		Timer _timer;

		uint16_t _sequenceNr;

		bool _homeAgent;
		bool _foreignAgent;
};

struct advertisement_header {
    uint8_t     type;           /* 0     Type = 9 (Router Advertisement) */
    uint8_t     code;           /* 1     Code = 0 (also has normal routing, otherwise it should be 16) */
    uint16_t    checksum;       /* 2-3   Checksum */
    uint8_t     addresses;      /* 4     Number of addresses = 1 */
    uint8_t     addr_size;      /* 5     Address Entry Size = 2 */
    uint16_t    lifetime;       /* 6-7   Lifetime */
    in_addr     address;        /* 8-11  First router address */
    uint32_t    addrPreference; /* 12-15 Preference of the router address = 0 */
};

struct mobile_advertisement_header {
    uint8_t     type;           /* 0    Type = 16 */
    uint8_t     length;         /* 1    Lenght = 6 + 4*N (with N number of care-of addresses) */
    uint16_t    seq_nr;         /* 2-3  Sequence Number */
    uint16_t    lifetime;       /* 4-5  Registration lifetime */
    uint8_t     flags;          /* 6    Flags */
    uint8_t     reserved;       /* 7    should be zero */
    uint32_t    address;        /* 8-11 Care-of-address */
};

CLICK_ENDDECLS
#endif
