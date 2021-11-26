/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "NPmath.p4"

const bit<16> TYPE_IPV4 = 0x800;


#define BLOOM_FILTER_ENTRIES 4445000
#define BLOOM_FILTER_BIT_WIDTH 1

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

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header colors_t {
	bit<8> red1;
	bit<8> green1;
	bit<8> blue1;

	bit<8> red2;
	bit<8> green2;
	bit<8> blue2;

	bit<8> red3;
	bit<8> green3;
	bit<8> blue3;

	bit<8> red4;
	bit<8> green4;
	bit<8> blue4;

	bit<8> red5;
	bit<8> green5;
	bit<8> blue5;

	bit<8> red6;
	bit<8> green6;
	bit<8> blue6;

	bit<8> red7;
	bit<8> green7;
	bit<8> blue7;

	bit<8> red8;
	bit<8> green8;
	bit<8> blue8;

	bit<8> red9;
	bit<8> green9;
	bit<8> blue9;
}

header counts_t {
	bit<32> class_decision;
	bit<32> sequence;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t udp;
    colors_t colors;
    counts_t counts;
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
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        //transition parse_tcp;
        transition parse_udp;
    }
    
    state parse_udp {
        packet.extract(hdr.udp);
        transition parse_color;
    }

    state parse_color {
        packet.extract(hdr.colors);
        transition parse_counts;
     }
    state parse_counts {
        packet.extract(hdr.counts);
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

   
    register<bit<32>>(1) packets;
    bit<32> packetno=32w0; 
	
    register<bit<16>>(9) CNeuron1;
    register<bit<16>>(9) CNeuron2;
    register<bit<16>>(9) CNeuron3;
    register<bit<16>>(9) CNeuron4;
    register<bit<16>>(9) CNeuron5;
    register<bit<16>>(9) CNeuron6;
    register<bit<16>>(9) CNeuron7;
    register<bit<16>>(9) CNeuron8;
    register<bit<16>>(9) CNeuron9;
    register<bit<16>>(9) CNeuron10;
    register<bit<16>>(9) CNeuron11;
    register<bit<16>>(9) CNeuron12;
    register<bit<16>>(9) CNeuron13;
    register<bit<16>>(9) CNeuron14;
    register<bit<16>>(9) CNeuron15;
    register<bit<16>>(9) CNeuron16;

    register<bit<16>>(10000) Weighted1;
    register<bit<16>>(10000) Weighted2;
    register<bit<16>>(10000) Weighted3;
    register<bit<16>>(10000) Weighted4;
    register<bit<16>>(10000) Weighted5;
    register<bit<16>>(10000) Weighted6;
    register<bit<16>>(10000) Weighted7;
    register<bit<16>>(10000) Weighted8;
    register<bit<16>>(10000) Weighted9;
    register<bit<16>>(10000) Weighted10;
    register<bit<16>>(10000) Weighted11;
    register<bit<16>>(10000) Weighted12;
    register<bit<16>>(10000) Weighted13;
    register<bit<16>>(10000) Weighted14;
    register<bit<16>>(10000) Weighted15;
    register<bit<16>>(10000) Weighted16;   
 
    mul() Mul00;
    mul() Mul01;
    mul() Mul02;
    mul() Mul03;
    mul() Mul04;
    mul() Mul05;
    mul() Mul06;
    mul() Mul07;
    mul() Mul08;

    mul() Mul10;
    mul() Mul11;
    mul() Mul12;
    mul() Mul13;
    mul() Mul14;
    mul() Mul15;
    mul() Mul16;
    mul() Mul17;
    mul() Mul18;

    mul() Mul20;
    mul() Mul21;
    mul() Mul22;
    mul() Mul23;
    mul() Mul24;
    mul() Mul25;
    mul() Mul26;
    mul() Mul27;
    mul() Mul28;

    mul() Mul30;
    mul() Mul31;
    mul() Mul32;
    mul() Mul33;
    mul() Mul34;
    mul() Mul35;
    mul() Mul36;
    mul() Mul37;
    mul() Mul38;

    mul() Mul40;
    mul() Mul41;
    mul() Mul42;
    mul() Mul43;
    mul() Mul44;
    mul() Mul45;
    mul() Mul46;
    mul() Mul47;
    mul() Mul48;

    mul() Mul50;
    mul() Mul51;
    mul() Mul52;
    mul() Mul53;
    mul() Mul54;
    mul() Mul55;
    mul() Mul56;
    mul() Mul57;
    mul() Mul58;

    mul() Mul60;
    mul() Mul61;
    mul() Mul62;
    mul() Mul63;
    mul() Mul64;
    mul() Mul65;
    mul() Mul66;
    mul() Mul67;
    mul() Mul68;

    mul() Mul00;
    mul() Mul01;
    mul() Mul02;
    mul() Mul03;
    mul() Mul04;
    mul() Mul05;
    mul() Mul06;
    mul() Mul07;
    mul() Mul08;

    mul() Mul00;
    mul() Mul01;
    mul() Mul02;
    mul() Mul03;
    mul() Mul04;
    mul() Mul05;
    mul() Mul06;
    mul() Mul07;
    mul() Mul08;

    mul() Mul00;
    mul() Mul01;
    mul() Mul02;
    mul() Mul03;
    mul() Mul04;
    mul() Mul05;
    mul() Mul06;
    mul() Mul07;
    mul() Mul08;

    mul() Mul00;
    mul() Mul01;
    mul() Mul02;
    mul() Mul03;
    mul() Mul04;
    mul() Mul05;
    mul() Mul06;
    mul() Mul07;
    mul() Mul08;

    mul() Mul00;
    mul() Mul01;
    mul() Mul02;
    mul() Mul03;
    mul() Mul04;
    mul() Mul05;
    mul() Mul06;
    mul() Mul07;
    mul() Mul08;

    mul() Mul00;
    mul() Mul01;
    mul() Mul02;
    mul() Mul03;
    mul() Mul04;
    mul() Mul05;
    mul() Mul06;
    mul() Mul07;
    mul() Mul08;

    mul() Mul00;
    mul() Mul01;
    mul() Mul02;
    mul() Mul03;
    mul() Mul04;
    mul() Mul05;
    mul() Mul06;
    mul() Mul07;
    mul() Mul08;

    mul() Mul00;
    mul() Mul01;
    mul() Mul02;
    mul() Mul03;
    mul() Mul04;
    mul() Mul05;
    mul() Mul06;
    mul() Mul07;
    mul() Mul08;

    mul() Mul00;
    mul() Mul01;
    mul() Mul02;
    mul() Mul03;
    mul() Mul04;
    mul() Mul05;
    mul() Mul06;
    mul() Mul07;
    mul() Mul08;


    bit<32> final_class=32w0;


    action drop() {
        mark_to_drop(standard_metadata);
    }

     action compute_hashes(bit<8> colorR, bit<8> colorG, bit<8> colorB){
       //here all the colors are considered to create a hash address for the register position
       hash(filter_address, HashAlgorithm.crc32, (bit<32>)0, {colorR,
                                                           colorG,
                                                           colorB},
                                                           (bit<32>)BLOOM_FILTER_ENTRIES);

    }

    action set_port(egressSpec_t port) {
	standard_metadata.egress_spec=port;
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action class_value(bit<32> value) {
	final_class=value;
    }
 
    table forwarding {
	key = {
		hdr.udp.dstPort: exact;
	}
	actions = {
		set_port;
		drop;
	}
    }
    
    apply {

        if (hdr.ipv4.isValid()) {

	    packets.read(packetno,0);
	    packetno=packetno+1;
	    packets.write(0,packetno)

	    forwarding.apply();
	    
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

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        //packet.emit(hdr.tcp);
	packet.emit(hdr.udp);
	//packet.emit(hdr.colors);
	packet.emit(hdr.counts);
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
