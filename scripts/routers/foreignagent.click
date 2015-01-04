
///===========================================================================///
/// An IP router with 2 interfaces.
///===========================================================================///

elementclass ForeignAgent
{
$private_address, $public_address, $default_gateway
|
    infobase :: ForeignAgentInfobase($public_address)

    mobilityAgentAdvertiser :: MobilityAgentAdvertiser(SRC_IP $private_address,
                                                       CARE_OF_ADDRESS $public_address,
                                                       HOME_AGENT false,
                                                       FOREIGN_AGENT true,
                                                       MinAdvertisementInterval 9,
                                                       MaxAdvertisementInterval 9,
                                                       AdvertisementLifetime 27,
                                                       RegistrationLifetime 100,
                                                       Busy false)

    // Shared IP input path and routing table
    ip :: Strip(14)
        -> CheckIPHeader
        -> regs::IPClassifier(src or dst udp port 434 or icmp type unreachable, -)[1]
        -> rt :: StaticIPLookup(
            $private_address:ip/32 0,
            $public_address:ip/32 0,
            $private_address:ipnet 1,
            $public_address:ipnet $default_gateway 2);

    // ARP responses are copied to each ARPQuerier and the host.
    arpt :: Tee(2);

    // Input and output paths for eth0
    c0 :: Classifier(12/0806 20/0001, 12/0806 20/0002, -);
    input[0]
        -> checkIfAgentSolicitation :: CheckIfAgentSolicitation[1]
        -> HostEtherFilter($private_address:eth)
        -> c0;

    c0[0] -> ar0 :: ARPResponder($private_address) -> [0]output;
    arpq0 :: ARPQuerier($private_address) -> [0]output;
    c0[1] -> arpt;
    arpt[0] -> [1]arpq0;
    c0[2] -> Paint(1) -> ip;

    // Respond to agent solicitations
    checkIfAgentSolicitation[0] -> mobilityAgentAdvertiser

    // Input and output paths for eth1
    c1 :: Classifier(12/0806 20/0001, 12/0806 20/0002, -);
    input[1] -> HostEtherFilter($public_address:eth) -> c1;
    c1[0] -> ar1 :: ARPResponder($public_address) -> [1]output;
    arpq1 :: ARPQuerier($public_address) -> [1]output;
    c1[1] -> arpt;
    arpt[1] -> [1]arpq1;
    c1[2] -> Paint(2) -> ip;

    // Local delivery
    rt[0]
        -> checkIfEncapsulated :: CheckIfEncapsulated[1]
        -> [2]output

    checkIfEncapsulated[0]
        -> StripIPHeader
        -> CheckIPHeader
        -> [0]arpq0

    // Relay registration requests and replies
    regs[0]
        -> Unstrip(14)
        -> relayRegistration :: RelayRegistration(infobase, PRIVATE_IP $private_address)[0]
        -> MarkIPHeader(0)
        -> SetIPChecksum
        -> [0]arpq0

    relayRegistration[1]
        -> Strip(14)
        -> SetIPChecksum
        -> rt

    // Forwarding path for eth0
    rt[1] -> DropBroadcasts
        -> cp0 :: PaintTee(1)
        -> gio0 :: IPGWOptions($private_address)
        -> FixIPSrc($private_address)
        -> dt0 :: DecIPTTL
        -> fr0 :: IPFragmenter(1500)
        -> [0]arpq0;

    dt0[1] -> ICMPError($private_address, timeexceeded) -> rt;
    fr0[1] -> ICMPError($private_address, unreachable, needfrag) -> rt;
    gio0[1] -> ICMPError($private_address, parameterproblem) -> rt;
    cp0[1] -> ICMPError($private_address, redirect, host) -> rt;

    // Forwarding path for eth1
    rt[2] -> DropBroadcasts
        -> cp1 :: PaintTee(2)
        -> gio1 :: IPGWOptions($public_address)
        -> FixIPSrc($public_address)
        -> dt1 :: DecIPTTL
        -> fr1 :: IPFragmenter(1500)
        -> [0]arpq1;

    dt1[1] -> ICMPError($public_address, timeexceeded) -> rt;
    fr1[1] -> ICMPError($public_address, unreachable, needfrag) -> rt;
    gio1[1] -> ICMPError($public_address, parameterproblem) -> rt;
    cp1[1] -> ICMPError($public_address, redirect, host) -> rt;

    // Send advertisements to find mobile nodes
    mobilityAgentAdvertiser -> [0]arpq0;
}
