#include <core.p4>
#include <v1model.p4>


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_MSLP = 0x88B5;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header mslp_label_t {
    bit<20> label;
    bit<1>  s;
    bit<8>  ttl;
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

struct metadata {
    macAddr_t nextHopMac;
    bit<1>    needs_tunnel;
    bit<20>   tunnel_label;
}



struct headers {
    ethernet_t ethernet;
    mslp_label_t[3] mslp_stack;
    ipv4_t ipv4;
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
            default: accept;
        }
    }

    // IPv4 parser
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            default: accept;
        }
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

    action drop() {
        mark_to_drop(standard_metadata);
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

    action setTunnel(bit<20> labelr4, bit<20> labelr3, bit<20> labelr2) {
        hdr.mslp_stack[0].setValid();

        hdr.mslp_stack[0].label = labelr4;
        hdr.mslp_stack[0].s = 0;

        hdr.mslp_stack[1].setValid();

        hdr.mslp_stack[1].label = labelr3;
        hdr.mslp_stack[1].s = 0;

        hdr.mslp_stack[2].setValid();

        hdr.mslp_stack[2].label = labelr2;
        hdr.mslp_stack[2].s = 1;  // Bottom of stack
    }



    table mplsTunnel {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            setTunnel;
            NoAction;
        }
        size = 256;
    }


     
    apply {
        if (hdr.ipv4.isValid()) {
            if (ipv4Lpm.apply().hit) {
                mplsTunnel.apply();
                internalMacLookup.apply();
            }
            else {
                drop();
            }
        } else {
            drop();
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
        if (meta.needs_tunnel == 1) {
            //hdr.mslp_stack.push_front();
            hdr.mslp_stack[0].label = meta.tunnel_label;
            hdr.mslp_stack[0].ttl   = hdr.ipv4.ttl;
            hdr.mslp_stack[0].s     = 1; // 's' = bottom of stack (1 porque é o único neste exemplo)
            hdr.ethernet.etherType = TYPE_MSLP; // muda EtherType para o protocolo MSLP
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
        packet.emit(hdr.mslp_stack);
        packet.emit(hdr.ipv4);
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
