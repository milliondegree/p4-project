/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_SRCROUTING = 0x1234;

#define MAX_HOPS 5

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header srcRoute_t {
    bit<1>    bos;
    bit<15>   port;
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
    /* empty */
}

struct headers {
    ethernet_t              ethernet;
    // array of source routing headers
    srcRoute_t[MAX_HOPS]    srcRoutes;
    ipv4_t                  ipv4;
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

    // extract the etherType field to decide the next state
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x1234: parse_srcRouting;
            0x800:  parse_ipv4;
            default: accept;
        }
    }

    state parse_srcRouting {
        // if not the last hop, get the next element of the array
        // we can take initial index is [-1], so next is [0]
        // if last hop, prase ipv4
        packet.extract(hdr.srcRoutes.next);
        transition select(hdr.srcRoutes.last.bos) {
            0: parse_srcRouting;
            default: parse_ipv4;
        }
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
    apply {  }
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
    
    action srcRoute_nhop() {
        // get the egress port to next hop
        // remove the 1st element of souce routing header array
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;
        hdr.srcRoutes.pop_front(1);
    }
    // update etherType to ipv4 at last switch
    action srcRoute_finish() {
        hdr.ethernet.etherType = TYPE_IPV4;
    }
    // update ttl
    action update_ttl(){
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    apply {
        // ipv4 packet processing, add source routing header array
        if(!hdr.srcRoutes[0].isValid() && hdr.ipv4.isValid()) {
            hdr.srcRoutes[0].setValid();
            hdr.srcRoutes[1].setValid();
            if(hdr.ipv4.srcAddr == 0x0a000101 && hdr.ipv4.dstAddr == 0x0a000202)
            {
                hdr.srcRoutes[0].bos = (bit<1>)0x0;
                hdr.srcRoutes[0].port = (bit<15>)0x2;
                hdr.srcRoutes[1].bos = (bit<1>)0x1;
                hdr.srcRoutes[1].port = (bit<15>)0x1;
                hdr.ethernet.etherType = TYPE_SRCROUTING;
                hdr.ethernet.dstAddr = 0x080000000222;
            }
            else if(hdr.ipv4.srcAddr == 0x0a000202 && hdr.ipv4.dstAddr == 0x0a000101)
            {
                hdr.srcRoutes[0].bos = (bit<1>)0x0;
                hdr.srcRoutes[0].port = (bit<15>)0x2;
                hdr.srcRoutes[1].bos = (bit<1>)0x1;
                hdr.srcRoutes[1].port = (bit<15>)0x1;
                hdr.ethernet.etherType = TYPE_SRCROUTING;
                hdr.ethernet.dstAddr = 0x080000000111;
            }
        }

        // source routing packet processing
        if (hdr.srcRoutes[0].isValid()){
            // the last hop to set the etherType to IP
            if(hdr.srcRoutes[0].bos == 0x1) {
                srcRoute_finish();
            }
            // get port to next hop, 
            // and pop-up 1st element of source routing header array
            srcRoute_nhop();
            // update the ttl at every hop
            if (hdr.ipv4.isValid()){
                update_ttl();
            }
        }
        // else{
        //     drop();
        // } 
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
