
///===========================================================================///
/// An IP router with 1 interface.
///===========================================================================///

elementclass IPRouter1int
{
$addr_info, $gateway
|
    // Shared IP input path and routing table
    ip :: Strip(14)
        //-> IPPrint("test")
        -> CheckIPHeader
        -> rt :: StaticIPLookup(
            $addr_info:ip/32 0,
            $addr_info:ipnet 1,
            0.0.0.0/0.0.0.0 $gateway 1);

    // ARP responses are copied to each ARPQuerier and the host.
    arpt :: Tee(1);

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
    rt[1] -> DropBroadcasts
        -> gio0 :: IPGWOptions($addr_info)
        -> FixIPSrc($addr_info)
        -> dt0 :: DecIPTTL
        -> fr0 :: IPFragmenter(1500)
        -> [0]arpq0;

    dt0[1] -> ICMPError($addr_info, timeexceeded) -> rt;
    fr0[1] -> ICMPError($addr_info, unreachable, needfrag) -> rt;
    gio0[1] -> ICMPError($addr_info, parameterproblem) -> rt;

}
