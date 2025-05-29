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
    bit<3>  exp;
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
    bit<1> pop_label;
    bit<2> label_index;
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
            TYPE_IPV4: parse_ipv4;
            TYPE_MSLP: parse_mslp_label;
            default: accept;
        }
    }

    


    state parse_mslp_label {
        // initialize label_index = 0 before entering loop
        label_index = 0;
        transition parse_mslp_stack;
    }

    state parse_mslp_stack {
        // bounds check: max 3 labels
        transition select(label_index) {
            0: parse_label_0;
            1: parse_label_1;
            2: parse_label_2;
            default: accept;
        }
    }

    state parse_label_0 {
        packet.extract(hdr.mslp_stack[0]);
        transition select(hdr.mslp_stack[0].s) {
            1: parse_ipv4;
            0: parse_label_1;
        }
    }

    state parse_label_1 {
        packet.extract(hdr.mslp_stack[1]);
        transition select(hdr.mslp_stack[1].s) {
            1: parse_ipv4;
            0: parse_label_2;
        }
    }

    state parse_label_2 {
        packet.extract(hdr.mslp_stack[2]);
        transition parse_ipv4;  // max stack depth = 3
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

    action set_pop_and_forward(bit<9> port, macAddr_t nextHop) {
        standard_metadata.egress_spec = port;
        meta.nextHopMac = nextHop;
        meta.pop_label = 1;
    }

    table mslp_forward {
        key = {
            hdr.mslp_stack[0].label: exact;
        }
        actions = {
            set_pop_and_forward;
            drop;
        }
        size = 256;
        default_action = drop;
    }


     
    apply {
        if (hdr.mslp_stack[0].isValid()) {
            mslp_forward.apply();
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
        if (hdr.mslp_stack[0].isValid()) {
            // Invalidate top label
            hdr.mslp_stack[0].setInvalid();
        
            // Shift labels down (optional)
            // For example, make label[1] into label[0]
            if (hdr.mslp_stack[1].isValid()) {
                hdr.mslp_stack[0] = hdr.mslp_stack[1];
                hdr.mslp_stack[1].setInvalid();
            }
        
            // Then update etherType accordingly
            if (!hdr.mslp_stack[1].isValid() && !hdr.mslp_stack[2].isValid()) {
                hdr.ethernet.etherType = TYPE_IPV4;
            } else {
                hdr.ethernet.etherType = TYPE_MSLP;
            }
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