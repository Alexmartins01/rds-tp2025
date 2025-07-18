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

struct metadata {
    macAddr_t nextHopMac;
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
    /**
     * a parser always begins in the start state
     * a state can invoke other state with two methods
     * transition <next-state>
     * transition select(<expression>) -> works like a switch case
     */
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_MSLP: parse_mslp_label;
            TYPE_IPV4: parse_ipv4;
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

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
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


    

    action popFwdLast(bit<9> port, macAddr_t nextHop) {
        hdr.mslp_stack[0].label = hdr.mslp_stack[1].label;
        hdr.mslp_stack[0].s = hdr.mslp_stack[1].s;
        hdr.mslp_stack[1].setInvalid();

        standard_metadata.egress_spec = port;
        meta.nextHopMac = nextHop;
    }

    action popFwdShift(bit<9> port, macAddr_t nextHop) {
        hdr.mslp_stack[0].label = hdr.mslp_stack[1].label;
        hdr.mslp_stack[0].s = hdr.mslp_stack[1].s;

        hdr.mslp_stack[1].label = hdr.mslp_stack[2].label;
        hdr.mslp_stack[1].s = hdr.mslp_stack[2].s;

        hdr.mslp_stack[2].setInvalid();

        standard_metadata.egress_spec = port;
        meta.nextHopMac = nextHop;
    }

    table mslpTunnel {
        key = {
            hdr.mslp_stack[0].label: exact;
        }
        actions = {
            popFwdLast;
            popFwdShift;
            drop;
        }
        size = 256;
        default_action = drop;
    }


     
    apply {
        if (hdr.ipv4.isValid()) {
            if (hdr.mslp_stack[0].isValid()) {
                mslpTunnel.apply();
            } else{ 
                if (ipv4Lpm.apply().hit){
                    internalMacLookup.apply();
                }
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
        packet.emit(hdr.mslp_stack); // pode estar vazia
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