#ifndef CLICK_MOBILITYAGENTADVERTISER_HH
#define CLICK_MOBILITYAGENTADVERTISER_HH
#include <click/element.hh>
#include <click/timer.hh>

CLICK_DECLS

class MobilityAgentAdvertiser : public Element {
    public:
        MobilityAgentAdvertiser();
        ~MobilityAgentAdvertiser();

        const char *class_name() const { return "MobilityAgentAdvertiser"; }
        const char *port_count() const { return "0-1/1"; }
        const char *processing() const { return PUSH; }

        int configure(Vector<String>&, ErrorHandler*);

        static String readMaxAdvertisementInterval(Element* e, void* thunk);
        static String readMinAdvertisementInterval(Element* e, void* thunk);
        static String readAdvertisementLifetime(Element* e, void* thunk);
        static String readRegistrationLifetime(Element* e, void* thunk);

        static int writeMaxAdvertisementInterval(const String& conf, Element* e, void* thunk, ErrorHandler* errh);
        static int writeMinAdvertisementInterval(const String& conf, Element* e, void* thunk, ErrorHandler* errh);
        static int writeAdvertisementLifetime(const String& conf, Element* e, void* thunk, ErrorHandler* errh);
        static int writeRegistrationLifetime(const String& conf, Element* e, void* thunk, ErrorHandler* errh);

        void add_handlers();

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

        // The maximum time allowed between sending multicast Router Advertisements from the interface, in seconds.
        // Must be no less than 4 seconds and no greater than 1800 seconds.
        // Default: 600 seconds
        unsigned _maxAdvertisementInterval;

        // The minimum time allowed between sending unsolicited multicast Router Advertisements from the interface, in seconds.
        // Must be no less than 3 seconds and no greater than MaxAdvertisementInterval.
        // Default: 0.75 * MaxAdvertisementInterval
        unsigned _minAdvertisementInterval;

        // The value to be placed in the Lifetime field of Router Advertisements sent from the interface, in seconds.
        // Must be no less than MaxAdvertisementInterval and no greater than 9000 seconds.
        // Default: 3 * MaxAdvertisementInterval
        unsigned _advertisementLifetime;

        // The longest lifetime (measured in seconds) that this agent is willing to accept in any Registration Request.
        // A value of 0xffff indicates infinity. This field has no relation to the "Lifetime" field within the
        // ICMP Router Advertisement portion of the Agent Advertisement.
        // Set to 0xffff in this code when not specified.
        uint16_t _registrationLifetime;
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
