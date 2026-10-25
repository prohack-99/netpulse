@load policy/tuning/json-logs.zeek
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ssl
@load base/frameworks/logging

# NetPulse: write ICMP conn.log rows ~15s after last packet (default 5 min)
redef icmp_inactivity_timeout = 15 sec;

# ---- NetPulse live ICMP: per-packet ICMP log ----
module IcmpLive;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:     time   &log;
        orig_h: addr   &log;
        resp_h: addr   &log;
        itype:  port   &log;
        icode:  port   &log;
        dir:    string &log;
    };

    global log_icmp_live: event(rec: Info);
}

event zeek_init()
{
    Log::create_stream(IcmpLive::LOG, [$columns=Info, $ev=log_icmp_live,
                                       $path="icmp_live"]);
}

event icmp_sent(c: connection, icmp: icmp_info)
{
    Log::write(IcmpLive::LOG, [$ts=network_time(), $orig_h=c$id$orig_h,
                               $resp_h=c$id$resp_h, $itype=c$id$orig_p,
                               $icode=c$id$resp_p, $dir="sent"]);
}

event icmp_echo_request(c: connection, icmp: icmp_info, id: count, seq: count, payload: string)
{
    Log::write(IcmpLive::LOG, [$ts=network_time(), $orig_h=c$id$orig_h,
                               $resp_h=c$id$resp_h, $itype=c$id$orig_p,
                               $icode=c$id$resp_p, $dir="sent"]);
}

event icmp_echo_reply(c: connection, icmp: icmp_info, id: count, seq: count, payload: string)
{
    Log::write(IcmpLive::LOG, [$ts=network_time(), $orig_h=c$id$orig_h,
                               $resp_h=c$id$resp_h, $itype=c$id$orig_p,
                               $icode=c$id$resp_p, $dir="reply"]);
}


# ---- NetPulse ARP: Zeek has no arp.log by default, so write one ----
module NetPulseARP;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:      time   &log;
        op:      string &log;
        src_mac: string &log;
        dst_mac: string &log;
        spa:     addr   &log;
        sha:     string &log;
        tpa:     addr   &log;
        tha:     string &log;
    };
}

event zeek_init()
{
    Log::create_stream(NetPulseARP::LOG, [$columns=Info, $path="arp"]);
}

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
{
    Log::write(NetPulseARP::LOG, [$ts=network_time(), $op="request",
        $src_mac=mac_src, $dst_mac=mac_dst, $spa=SPA, $sha=SHA, $tpa=TPA, $tha=THA]);
}

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
{
    Log::write(NetPulseARP::LOG, [$ts=network_time(), $op="reply",
        $src_mac=mac_src, $dst_mac=mac_dst, $spa=SPA, $sha=SHA, $tpa=TPA, $tha=THA]);
}

# NetPulse: log IPv4 packets whose protocol is not ICMP/TCP/UDP
# (IGMP, GRE, ESP, OSPF, VRRP, PIM, SCTP ...). Zeek writes no conn.log row
# for these, so the "Other" tab reads this log instead.
module OtherIp;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:     time   &log;
        orig_h: addr   &log;
        resp_h: addr   &log;
        proto:  count  &log;
        len:    count  &log;
    };
}

event zeek_init()
{
    Log::create_stream(OtherIp::LOG, [$columns=Info, $path="other_ip"]);
}

event raw_packet(p: raw_pkt_hdr)
{
    if ( ! p?$ip )
        return;

    local n = p$ip$p;
    if ( n == 1 || n == 6 || n == 17 )
        return;

    Log::write(OtherIp::LOG, [$ts=network_time(), $orig_h=p$ip$src,
                              $resp_h=p$ip$dst, $proto=n, $len=p$ip$len]);
}

