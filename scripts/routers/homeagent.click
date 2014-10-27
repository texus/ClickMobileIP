///===========================================================================///
/// An IP router with 2 interfaces.
///===========================================================================///

elementclass HomeAgent
{
$private_address, $public_address, $default_gateway
|
    infobase :: HomeAgentInfobase

	// Shared IP input path and routing table
	ip :: Strip(14)
	-> CheckIPHeader
	-> rt :: StaticIPLookup(
		$private_address:ip/32 0,
		$public_address:ip/32 0,
		$private_address:ipnet 1,
		$public_address:ipnet $default_gateway 2);

	// ARP responses are copied to each ARPQuerier and the host.
	arpt :: Tee(2);

	// Input and output paths for eth0
	c0 :: Classifier(12/0806 20/0001, 12/0806 20/0002, -);
	input[0] -> HostEtherFilter($private_address:eth) -> c0;
	c0[0] -> ar0 :: ARPResponder($private_address) -> [0]output;
	arpq0 :: ARPQuerier($private_address) -> [0]output;
	c0[1] -> arpt;
	arpt[0] -> [1]arpq0;
	c0[2] -> Paint(1) -> ip;

	// Input and output paths for eth1
	c1 :: Classifier(12/0806 20/0001, 12/0806 20/0002, -);
	input[1] -> HostEtherFilter($public_address:eth) -> c1;
	c1[0] -> ar1 :: ARPResponder($public_address) -> [1]output;
	arpq1 :: ARPQuerier($public_address) -> [1]output;
	c1[1] -> arpt;
	arpt[1] -> [1]arpq1;
	c1[2] -> Paint(2) -> ip;

	// Local delivery
	rt[0] -> [2]output

	// Forwarding path for eth0
	rt[1] -> DropBroadcasts
	    -> cp0 :: PaintTee(1)
	    -> gio0 :: IPGWOptions($private_address)
	    -> FixIPSrc($private_address)
	    -> dt0 :: DecIPTTL
	    -> fr0 :: IPFragmenter(1500)
	    -> mobile_routing :: HomeAgentMobileNodeRouting(infobase)[0]
	    -> [0]arpq0;

	// The mobile node is not home, so tunnel the package to its care-of-address
	mobile_routing[1]
        -> Encapsulator(infobase, SRC_IP $public_address)
        -> arpq1;

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
    MobilityAgentAdvertiser(SRC_IP $public_address, INTERVAL 1, HOME_AGENT true, FOREIGN_AGENT false)
        -> EtherEncap(0x0800, $private_address:eth, FF:FF:FF:FF:FF:FF)
        -> [0]output;
}
