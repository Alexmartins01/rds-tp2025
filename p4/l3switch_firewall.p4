#include <core.p4>
#include <v1model.p4>

#define BLOOM_FILTER_ENTRIES 4096
#define BLOOM_FILTER_BIT_WIDTH 1

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP = 6;
const bit<8> TYPE_UDP = 17;
const bit<16> TYPE_MSLP = 0x88B5;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header mslp_label_t {
    bit<15> label;
    bit<1>  s;
}


header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;

}

struct metadata {
    macAddr_t nextHopMac;
    bit<1> needs_decap;
}


struct headers {
    ethernet_t   ethernet;
    mslp_label_t[3] mslp_stack;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    

    // Ethernet parser
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_MSLP: parse_mslp_label;
            default: accept;
        }
    }



    state parse_mslp_label {
        transition parse_mslp_0;
    }

    state parse_mslp_0 {
        packet.extract(hdr.mslp_stack[0]);
        transition select(hdr.mslp_stack[0].s) {
            1: parse_ipv4;
            0: parse_mslp_1;
        }
    }

    state parse_mslp_1 {
        packet.extract(hdr.mslp_stack[1]);
        transition select(hdr.mslp_stack[1].s) {
            1: parse_ipv4;
            0: parse_mslp_2;
        }
    }

    state parse_mslp_2 {
        packet.extract(hdr.mslp_stack[2]);
        transition parse_ipv4;
    }

    // IPv4 parser
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }
    
    state parse_tcp{
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp{
        packet.extract(hdr.udp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply { /* do nothing */  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_1;
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_2;
    bit<32> reg_pos_one; bit<32> reg_pos_two;
    bit<1> reg_val_one; bit<1> reg_val_two;
    bit<1> direction;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action compute_hashes(ip4Addr_t ipAddr1, ip4Addr_t ipAddr2, bit<16> port1, bit<16> port2, bit<8> protocol){
       //Get register position
       hash(reg_pos_one, HashAlgorithm.crc16, (bit<32>)0, {ipAddr1,
                                                           ipAddr2,
                                                           port1,
                                                           port2,
                                                           protocol},
                                                           (bit<32>)BLOOM_FILTER_ENTRIES);

       hash(reg_pos_two, HashAlgorithm.crc32, (bit<32>)0, {ipAddr1,
                                                           ipAddr2,
                                                           port1,
                                                           port2,
                                                           protocol},
                                                           (bit<32>)BLOOM_FILTER_ENTRIES);
    }

    action forward(bit<9>  egressPort, macAddr_t nextHopMac) {
        standard_metadata.egress_spec = egressPort;
        meta.nextHopMac = nextHopMac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4Lpm{
        key = {hdr.ipv4.dstAddr : lpm;}
        actions = {
            forward;
            drop;
        }
        size = 256;
        default_action = drop;
    }

    

    action rewriteMacs(macAddr_t srcMac) {
        hdr.ethernet.srcAddr = srcMac;
        hdr.ethernet.dstAddr = meta.nextHopMac;
    }

    table internalMacLookup{
        key = {standard_metadata.egress_spec: exact;}
        actions = { 
            rewriteMacs;
            drop;
        }
        size = 256;
        default_action = drop;
    }

    action setDecap() {
        meta.needs_decap = 1;
    }

    table mslpDecap {
        key = {
            hdr.mslp_stack[0].label: exact;
        }
        actions = {
            setDecap;
            drop;
        }
        size = 256;
        default_action = drop;
    }
    
    apply {
        if (hdr.mslp_stack[0].isValid()) {
            mslpDecap.apply();  // marca se deve remover os labels no egress
        }

        if(hdr.ipv4.isValid()) {
            if(ipv4Lpm.apply().hit) {
                if (hdr.udp.isValid() || hdr.tcp.isValid()) {

                    // ---------- FIREWALL ---------- //


                    if(standard_metadata.ingress_port == 2) { // vem de dentro
                        if(hdr.ipv4.protocol == TYPE_TCP) { // verificas protocolo e aplica hash
                            compute_hashes(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol);
                        } else if (hdr.ipv4.protocol == TYPE_UDP) {
                            compute_hashes(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol);
                        }
                        // we update the bloom filter and add the entry
                        bloom_filter_1.write(reg_pos_one, 1);
                        bloom_filter_2.write(reg_pos_two, 1);
                    } else { // vem de fora
                        if(hdr.ipv4.protocol == TYPE_TCP) {
                            compute_hashes(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.tcp.dstPort, hdr.tcp.srcPort, hdr.ipv4.protocol);
                        } else if(hdr.ipv4.protocol == TYPE_UDP) {
                            compute_hashes(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.udp.dstPort, hdr.udp.srcPort, hdr.ipv4.protocol);
                        }
                        // only allow flow to pass if both entries are set
                        bloom_filter_1.read(reg_val_one, reg_pos_one);
                        bloom_filter_2.read(reg_val_two, reg_pos_two);

                        if(reg_val_one != 1 || reg_val_two != 1) {
                            drop(); return;
                        }
                    }

                    // ---------- FIM FIREWALL ---------- //
                }

                internalMacLookup.apply();
            }
        } else {
            drop(); return;
        }
    }
}
    

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    

    apply {
        if (meta.needs_decap == 1) {
            // Invalidate all MPLS labels in the stack
            hdr.mslp_stack[0].setInvalid();

            // Update Ethernet EtherType to IPv4
            hdr.ethernet.etherType = TYPE_IPV4;
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    /* The IPv4 Header was changed, it needs new checksum*/
    apply { 
        update_checksum(
	        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16); }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }

}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
/*
 * Architecture.
 *
 * M must be a struct.
 *
 * H must be a struct where every one if its members is of type
 * header, header stack, or header_union.
 *
 * package V1Switch<H, M>(Parser<H, M> p,
 *                      VerifyChecksum<H, M> vr,
 *                      Ingress<H, M> ig,
 *                      Egress<H, M> eg,
 *                      ComputeChecksum<H, M> ck,
 *                      Deparser<H> dep
 *                      );
 * you can define the blocks of your sowtware switch in the following way:
 */

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
