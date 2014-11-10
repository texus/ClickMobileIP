
///===========================================================================///
/// An IP router with 1 interface.
///===========================================================================///

elementclass MobileNode 
{
$addr_info, $gateway
|
    // Stores the information that multiple elements need to access
    infobase :: MobileNodeInfobase($gateway, $addr_info)

    // Shared IP input path and routing table
    ip :: Strip(14)
    //-> IPPrint("test")
    -> CheckIPHeader
   -> regs::IPClassifier(src or dst udp port 434, -)[1]
    -> rt :: StaticIPLookup(
        $addr_info:ip/32 0,
        $addr_info:ipnet 1,
        0.0.0.0/0.0.0.0 $gateway 1);

	// ARP responses are copied to each ARPQuerier and the host.
	arpt :: Tee(1);

    regs[0]
    ->RegisterNode(infobase)
    ->Discard //TODO resend requests if applicable
	
	// Input and output paths for eth0
	c0 :: Classifier(12/0806 20/0001, 12/0806 20/0002, -);
	input[0] -> HostEtherFilter($addr_info:eth) -> c0;
	c0[0] -> ar0 :: ARPResponder($addr_info) -> [0]output;
	arpq0 :: ARPQuerier($addr_info) -> [0]output;
	c0[1] -> arpt;
	arpt[0] -> [1]arpq0;
	c0[2] -> Paint(1) -> ip;
		
	// Local delivery
	rt[0] -> [1]output;
	
	// Forwarding path for eth0
	rt[1]
	-> processAdvertisements :: ProcessAdvertisements(infobase)[0]
	-> DropBroadcasts
	-> gio0 :: IPGWOptions($addr_info)
	-> FixIPSrc($addr_info)
	-> dt0 :: DecIPTTL
	-> fr0 :: IPFragmenter(1500)
	-> MobileNodeRouting(infobase)
	-> [0]arpq0;

    processAdvertisements[1]
        -> RegistrationRequester(infobase)
        -> [0]arpq0;

    // Send agent solicitations when not connected and there are no advertisements
    AgentSolicitation(infobase, SRC_IP $addr_info:ip)
        -> [0]arpq0;

	dt0[1] -> ICMPError($addr_info, timeexceeded) -> rt;
	fr0[1] -> ICMPError($addr_info, unreachable, needfrag) -> rt;
	gio0[1] -> ICMPError($addr_info, parameterproblem) -> rt;
	
}
