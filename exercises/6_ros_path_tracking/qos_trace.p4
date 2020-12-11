/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_TRACE = 0x5555;

/* IP protocols */
// const bit<8> PROTOCOLS_ICMP       =   1;
const bit<8> PROTOCOLS_TCP        =   6;
const bit<8> PROTOCOLS_UDP        =  17;



/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<2>  targetID_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

/* ip header having "tos" and "ecn" */
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    tos;   // tos priority
    bit<2>    ecn;  // Explicit Congestion Notification
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

header trace_t {
    targetID_t t1;
    targetID_t t2;
    targetID_t t3;
    targetID_t t4;
    bit<16> proto_id;
    bit<8> count;
}

struct metadata {
}

struct headers {
    ethernet_t   ethernet;
    trace_t      trace;
    ipv4_t       ipv4;
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

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_TRACE: parse_trace;
            default: accept;
        }
    }

    state parse_trace {
        packet.extract(hdr.trace);
        transition select(hdr.trace.proto_id) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
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

    action ipv4_forward(macAddr_t dstAddr, 
                        egressSpec_t port, 
                        targetID_t tid) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        // record the total count of devices passed
        hdr.trace.count = hdr.trace.count + 1;
        
        // record id of the current device.
        if(hdr.trace.count == 1)
            hdr.trace.t1 = tid;
        else if(hdr.trace.count == 2)
            hdr.trace.t2 = tid;
        else if(hdr.trace.count == 3)
            hdr.trace.t3 = tid;
        else if(hdr.trace.count == 4)
            hdr.trace.t4 = tid;
    }

/* actions for different traffic classes */
    action udp_tos() {
        hdr.ipv4.tos = 0xa;  // tos = 10
        hdr.ipv4.ecn = 0;   // always set enc = 0
    }

    //  action icmp_tos() {
    //     hdr.ipv4.tos = 0xa;  // tos = 10
    //     hdr.ipv4.ecn = 0;
    // }   

    action tcp_tos() {
        hdr.ipv4.tos = 0x14; // tos = 20
        hdr.ipv4.ecn = 0x0;
    }

    action general_tos() {
        hdr.ipv4.tos = 0x1e; // tos = 30
        hdr.ipv4.ecn = 0x0;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
            hdr.ipv4.tos: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            if(hdr.ipv4.protocol == PROTOCOLS_UDP)
                udp_tos();
            else if (hdr.ipv4.protocol == PROTOCOLS_TCP)
                tcp_tos();
            // else if (hdr.ipv4.protocol == PROTOCOLS_ICMP)
            //     icmp_tos();
            else
                general_tos();
            ipv4_lpm.apply();
        }
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
    apply {
    update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.tos,   // Differentiated Services
              hdr.ipv4.ecn,  // Explicit Congestion Notification
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.trace);
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
