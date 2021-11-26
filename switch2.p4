/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "NPmath.p4"

const bit<16> TYPE_IPV4 = 0x800;
typedef bit<4> PortId;
const PortId RECIRCULATE_IN_PORT = 0xD;
const PortId RECIRCULATE_OUT_PORT = 0xD;
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4

// Define constants for types of packets
#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6
#define N_SIZE 676
#define B_threshold 100

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

header FCR {
    bit<32> flag_value;
    bit<32> sqn;
    bit<169> CNeuronRes;
	bit<81> ConvRes1;
	bit<81> ConvRes2;
	bit<81> ConvRes3;
	bit<81> ConvRes4;
	bit<81> ConvRes5;
	bit<81> ConvRes6;
	bit<81> ConvRes7;
	bit<81> ConvRes8;
	bit<81> ConvRes9;
	bit<81> ConvRes10;
	bit<81> ConvRes11;
	bit<81> ConvRes12;
	bit<81> ConvRes13;
	bit<81> ConvRes14;
	bit<81> ConvRes15;
	bit<81> ConvRes16;
	bit<81> ConvRes17;
	bit<81> ConvRes18;
	bit<81> ConvRes19;
	bit<81> ConvRes20;
	bit<81> ConvRes21;
	bit<81> ConvRes22;
	bit<81> ConvRes23;
	bit<81> ConvRes24;
	bit<81> ConvRes25;
	bit<81> ConvRes26;
	bit<81> ConvRes27;
	bit<81> ConvRes28;
	bit<81> ConvRes29;
	bit<81> ConvRes30;
	bit<81> ConvRes31;
	bit<81> ConvRes32;
	bit<81> ConvRes33;
	bit<81> ConvRes34;
	bit<81> ConvRes35;
	bit<81> ConvRes36;
	bit<81> ConvRes37;
	bit<81> ConvRes38;
	bit<81> ConvRes39;
	bit<81> ConvRes40;
	bit<81> ConvRes41;
	bit<81> ConvRes42;
	bit<81> ConvRes43;
	bit<81> ConvRes44;
	bit<81> ConvRes45;
	bit<81> ConvRes46;
	bit<81> ConvRes47;
	bit<81> ConvRes48;
	bit<81> ConvRes49;
	bit<81> ConvRes50;
	bit<81> ConvRes51;
	bit<81> ConvRes52;
	bit<81> ConvRes53;
	bit<81> ConvRes54;
	bit<81> ConvRes55;
	bit<81> ConvRes56;
	bit<81> ConvRes57;
	bit<81> ConvRes58;
	bit<81> ConvRes59;
	bit<81> ConvRes60;
	bit<81> ConvRes61;
	bit<81> ConvRes62;
	bit<81> ConvRes63;
	bit<81> ConvRes64;
	bit<7> empty;

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
    FCR fcr;
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
	    transition parse_fcr;
    }	
    state parse_fcr {
        packet.extract(hdr.fcr);
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
    bit<32> sequence_no; 

	
    register<bit<25>>(8) CNeuron1;
    register<bit<25>>(8) CNeuron2;
    register<bit<25>>(8) CNeuron3;
    register<bit<25>>(8) CNeuron4;
    register<bit<25>>(8) CNeuron5;
    register<bit<25>>(8) CNeuron6;
    register<bit<25>>(8) CNeuron7;			//binary weights for the convolutional filters
    register<bit<25>>(8) CNeuron8;
    register<bit<25>>(8) CNeuron9;
    register<bit<25>>(8) CNeuron10;
    register<bit<25>>(8) CNeuron11;
    register<bit<25>>(8) CNeuron12;
    register<bit<25>>(8) CNeuron13;
    register<bit<25>>(8) CNeuron14;
    register<bit<25>>(8) CNeuron15;
    register<bit<25>>(8) CNeuron16;
    register<bit<25>>(8) CNeuron17;			//binary weights for the convolutional filters
    register<bit<25>>(8) CNeuron18;
    register<bit<25>>(8) CNeuron19;
    register<bit<25>>(8) CNeuron20;
    register<bit<25>>(8) CNeuron21;
    register<bit<25>>(8) CNeuron22;
    register<bit<25>>(8) CNeuron23;
    register<bit<25>>(8) CNeuron24;
    register<bit<25>>(8) CNeuron25;
    register<bit<25>>(8) CNeuron26;
    register<bit<25>>(8) CNeuron27;			//binary weights for the convolutional filters
    register<bit<25>>(8) CNeuron28;
    register<bit<25>>(8) CNeuron29;
    register<bit<25>>(8) CNeuron30;
    register<bit<25>>(8) CNeuron31;
    register<bit<25>>(8) CNeuron32;
    register<bit<25>>(8) CNeuron33;
    register<bit<25>>(8) CNeuron34;
    register<bit<25>>(8) CNeuron35;
    register<bit<25>>(8) CNeuron36;
    register<bit<25>>(8) CNeuron37;			//binary weights for the convolutional filters
    register<bit<25>>(8) CNeuron38;
    register<bit<25>>(8) CNeuron39;
    register<bit<25>>(8) CNeuron40;
    register<bit<25>>(8) CNeuron41;
    register<bit<25>>(8) CNeuron42;
    register<bit<25>>(8) CNeuron43;
    register<bit<25>>(8) CNeuron44;
    register<bit<25>>(8) CNeuron45;
    register<bit<25>>(8) CNeuron46;
    register<bit<25>>(8) CNeuron47;			//binary weights for the convolutional filters
    register<bit<25>>(8) CNeuron48;
    register<bit<25>>(8) CNeuron49;
    register<bit<25>>(8) CNeuron50;
    register<bit<25>>(8) CNeuron51;
    register<bit<25>>(8) CNeuron52;
    register<bit<25>>(8) CNeuron53;
    register<bit<25>>(8) CNeuron54;
    register<bit<25>>(8) CNeuron55;
    register<bit<25>>(8) CNeuron56;
    register<bit<25>>(8) CNeuron57;			//binary weights for the convolutional filters
    register<bit<25>>(8) CNeuron58;
    register<bit<25>>(8) CNeuron59;
    register<bit<25>>(8) CNeuron60;
    register<bit<25>>(8) CNeuron61;
    register<bit<25>>(8) CNeuron62;
    register<bit<25>>(8) CNeuron63;
    register<bit<25>>(8) CNeuron64;

			


    register<bit<81>>(1) CNeuronRes1;
    register<bit<81>>(1) CNeuronRes2;
    register<bit<81>>(1) CNeuronRes3;
    register<bit<81>>(1) CNeuronRes4;
    register<bit<81>>(1) CNeuronRes5;
    register<bit<81>>(1) CNeuronRes6;
    register<bit<81>>(1) CNeuronRes7;			//binary weights for the conResvolutionResal filters
    register<bit<81>>(1) CNeuronRes8;
    register<bit<81>>(1) CNeuronRes9;
    register<bit<81>>(1) CNeuronRes10;
    register<bit<81>>(1) CNeuronRes11;
    register<bit<81>>(1) CNeuronRes12;
    register<bit<81>>(1) CNeuronRes13;
    register<bit<81>>(1) CNeuronRes14;
    register<bit<81>>(1) CNeuronRes15;
    register<bit<81>>(1) CNeuronRes16;
    register<bit<81>>(1) CNeuronRes17;			//binary weights for the convolutional filters
    register<bit<81>>(1) CNeuronRes18;
    register<bit<81>>(1) CNeuronRes19;
    register<bit<81>>(1) CNeuronRes20;
    register<bit<81>>(1) CNeuronRes21;
    register<bit<81>>(1) CNeuronRes22;
    register<bit<81>>(1) CNeuronRes23;
    register<bit<81>>(1) CNeuronRes24;
    register<bit<81>>(1) CNeuronRes25;
    register<bit<81>>(1) CNeuronRes26;
    register<bit<81>>(1) CNeuronRes27;			//binary weights for the convolutional filters
    register<bit<81>>(1) CNeuronRes28;
    register<bit<81>>(1) CNeuronRes29;
    register<bit<81>>(1) CNeuronRes30;
    register<bit<81>>(1) CNeuronRes31;
    register<bit<81>>(1) CNeuronRes32;
    register<bit<81>>(1) CNeuronRes33;
    register<bit<81>>(1) CNeuronRes34;
    register<bit<81>>(1) CNeuronRes35;
    register<bit<81>>(1) CNeuronRes36;
    register<bit<81>>(1) CNeuronRes37;			//binary weights for the convolutional filters
    register<bit<81>>(1) CNeuronRes38;
    register<bit<81>>(1) CNeuronRes39;
    register<bit<81>>(1) CNeuronRes40;
    register<bit<81>>(1) CNeuronRes41;
    register<bit<81>>(1) CNeuronRes42;
    register<bit<81>>(1) CNeuronRes43;
    register<bit<81>>(1) CNeuronRes44;
    register<bit<81>>(1) CNeuronRes45;
    register<bit<81>>(1) CNeuronRes46;
    register<bit<81>>(1) CNeuronRes47;			//binary weights for the convolutional filters
    register<bit<81>>(1) CNeuronRes48;
    register<bit<81>>(1) CNeuronRes49;
    register<bit<81>>(1) CNeuronRes50;
    register<bit<81>>(1) CNeuronRes51;
    register<bit<81>>(1) CNeuronRes52;
    register<bit<81>>(1) CNeuronRes53;
    register<bit<81>>(1) CNeuronRes54;
    register<bit<81>>(1) CNeuronRes55;
    register<bit<81>>(1) CNeuronRes56;
    register<bit<81>>(1) CNeuronRes57;			//binary weights for the convolutional filters
    register<bit<81>>(1) CNeuronRes58;
    register<bit<81>>(1) CNeuronRes59;
    register<bit<81>>(1) CNeuronRes60;
    register<bit<81>>(1) CNeuronRes61;
    register<bit<81>>(1) CNeuronRes62;
    register<bit<81>>(1) CNeuronRes63;
    register<bit<81>>(1) CNeuronRes64;

    bit<81> NResponse1=0;
    bit<81> NResponse2=0;
    bit<81> NResponse3=0;
    bit<81> NResponse4=0;
    bit<81> NResponse5=0;
    bit<81> NResponse6=0;
    bit<81> NResponse7=0;			//binary weights for the conResvolutionResal filters
    bit<81> NResponse8=0;
  
	bit<81> temp_holder=0;


    bit<128> m1 = 0x55555555555555555555555555555555;
    bit<128> m2 = 0x33333333333333333333333333333333;
    bit<128> m4 = 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f;
    bit<128> m8 = 0x00ff00ff00ff00ff00ff00ff00ff00ff;
    bit<128> m16= 0x0000ffff0000ffff0000ffff0000ffff;
    bit<128> m32= 0x00000000ffffffff00000000ffffffff;
    bit<128> m64= 0x0000000000000000ffffffffffffffff;


    bit<25> CXNOROutput=0;					 //output of XNOR for the Convolutional layer					
    bit<1> CResponse=0;						 //convolutional response for each xnor-popcount operation
    bit<8> activated=0;
    bit<32> final_class=32w0;


    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_port(egressSpec_t port) {
	standard_metadata.egress_spec=2;
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

	//Convolutional layer XNOR, involving 1-bit operands
    action CXNOR(bit<25> weight, bit<25> pixel){
        CXNOROutput = weight^pixel;
        CXNOROutput = ~CXNOROutput;
    }
	//Convolutional layer popcount, only 1-bit
    action CBitCount(bit<25> bitInput){
	bit<128> x= (bit<128>)bitInput;
	x = (x & m1 ) + ((x >>  1) & m1 ); 
	x = (x & m2 ) + ((x >>  2) & m2 );
	x = (x & m4 ) + ((x >>  4) & m4 );
    x = (x & m8 ) + ((x >>  8) & m8 );
    x = (x & m16) + ((x >> 16) & m16);
	if (x>12) CResponse = 1;
	else CResponse = 0;
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

		/* *********************************************** */
		/*                            CONVOLUTIONAL LAYER                        */
		/* ********************************************** */

        bit<32> flag=hdr.fcr.sqn-1;
        bit<25> temp_weight1;
	bit<25> temp_weight2;
	bit<25> temp_weight3;
	bit<25> temp_weight4;
	bit<25> temp_weight5;
	bit<25> temp_weight6;
	bit<25> temp_weight7;
	bit<25> temp_weight8;
        bit<169> instr=hdr.fcr.CNeuronRes;
        bit<25> temp_window;
	bit<81> temp_res;

	packets.read(packetno,0);
	packetno=packetno+1;
	packets.write(0,packetno);
	
	CNeuron1.write(0,30);					//write weight values
	CNeuron1.write(1,190);
	CNeuron1.write(2,174);
	CNeuron1.write(3,461);
	CNeuron1.write(4,458);
	CNeuron1.write(5,461);
	CNeuron1.write(6,190);
	CNeuron1.write(7,119);
	CNeuron2.write(0,414);
	CNeuron2.write(1,468);
	CNeuron2.write(2,290);
	CNeuron2.write(3,358);
	CNeuron2.write(4,420);
	CNeuron2.write(5,500);
	CNeuron2.write(6,494);
	CNeuron2.write(7,71);
	CNeuron3.write(0,474);
	CNeuron3.write(1,184);
	CNeuron3.write(2,478);
	CNeuron3.write(3,239);
	CNeuron3.write(4,32);
	CNeuron3.write(5,256);
	CNeuron3.write(6,240);
	CNeuron3.write(7,44);
	CNeuron4.write(0,358);
	CNeuron4.write(1,77);
	CNeuron4.write(2,426);
	CNeuron4.write(3,23);
	CNeuron4.write(4,416);
	CNeuron4.write(5,384);
	CNeuron4.write(6,120);
	CNeuron4.write(7,395);
	CNeuron5.write(0,394);
	CNeuron5.write(1,285);
	CNeuron5.write(2,46);
	CNeuron5.write(3,74);
	CNeuron5.write(4,38);
	CNeuron5.write(5,106);
	CNeuron5.write(6,290);
	CNeuron5.write(7,456);
	CNeuron6.write(0,187);
	CNeuron6.write(1,140);
	CNeuron6.write(2,297);
	CNeuron6.write(3,181);
	CNeuron6.write(4,4);
	CNeuron6.write(5,382);
	CNeuron6.write(6,288);
	CNeuron6.write(7,222);
	CNeuron7.write(0,295);
	CNeuron7.write(1,262);
	CNeuron7.write(2,344);
	CNeuron7.write(3,156);
	CNeuron7.write(4,502);
	CNeuron7.write(5,35);
	CNeuron7.write(6,243);
	CNeuron7.write(7,161);
	CNeuron8.write(0,249);
	CNeuron8.write(1,135);
	CNeuron8.write(2,377);
	CNeuron8.write(3,392);
	CNeuron8.write(4,474);
	CNeuron8.write(5,68);
	CNeuron8.write(6,353);
	CNeuron8.write(7,14);
	CNeuron9.write(0,170);
	CNeuron9.write(1,63);
	CNeuron9.write(2,509);
	CNeuron9.write(3,476);
	CNeuron9.write(4,171);
	CNeuron9.write(5,311);
	CNeuron9.write(6,57);
	CNeuron9.write(7,365);
	CNeuron10.write(0,182);
	CNeuron10.write(1,187);
	CNeuron10.write(2,418);
	CNeuron10.write(3,64);
	CNeuron10.write(4,52);
	CNeuron10.write(5,506);
	CNeuron10.write(6,214);
	CNeuron10.write(7,53);
	CNeuron11.write(0,442);
	CNeuron11.write(1,313);
	CNeuron11.write(2,148);
	CNeuron11.write(3,79);
	CNeuron11.write(4,488);
	CNeuron11.write(5,131);
	CNeuron11.write(6,87);
	CNeuron11.write(7,0);
	CNeuron12.write(0,365);
	CNeuron12.write(1,35);
	CNeuron12.write(2,40);
	CNeuron12.write(3,367);
	CNeuron12.write(4,119);
	CNeuron12.write(5,402);
	CNeuron12.write(6,279);
	CNeuron12.write(7,303);
	CNeuron13.write(0,175);
	CNeuron13.write(1,480);
	CNeuron13.write(2,332);
	CNeuron13.write(3,11);
	CNeuron13.write(4,94);
	CNeuron13.write(5,230);
	CNeuron13.write(6,193);
	CNeuron13.write(7,478);
	CNeuron14.write(0,145);
	CNeuron14.write(1,500);
	CNeuron14.write(2,64);
	CNeuron14.write(3,123);
	CNeuron14.write(4,297);
	CNeuron14.write(5,389);
	CNeuron14.write(6,188);
	CNeuron14.write(7,312);
	CNeuron15.write(0,360);
	CNeuron15.write(1,43);
	CNeuron15.write(2,427);
	CNeuron15.write(3,477);
	CNeuron15.write(4,125);
	CNeuron15.write(5,186);
	CNeuron15.write(6,407);
	CNeuron15.write(7,5);
	CNeuron16.write(0,201);
	CNeuron16.write(1,166);
	CNeuron16.write(2,69);
	CNeuron16.write(3,83);
	CNeuron16.write(4,332);
	CNeuron16.write(5,116);
	CNeuron16.write(6,143);
	CNeuron16.write(7,309);
	CNeuron17.write(0,24);
	CNeuron17.write(1,221);
	CNeuron17.write(2,101);
	CNeuron17.write(3,138);
	CNeuron17.write(4,454);
	CNeuron17.write(5,27);
	CNeuron17.write(6,410);
	CNeuron17.write(7,233);
	CNeuron18.write(0,162);
	CNeuron18.write(1,97);
	CNeuron18.write(2,205);
	CNeuron18.write(3,323);
	CNeuron18.write(4,295);
	CNeuron18.write(5,406);
	CNeuron18.write(6,150);
	CNeuron18.write(7,212);
	CNeuron19.write(0,167);
	CNeuron19.write(1,18);
	CNeuron19.write(2,126);
	CNeuron19.write(3,310);
	CNeuron19.write(4,357);
	CNeuron19.write(5,279);
	CNeuron19.write(6,194);
	CNeuron19.write(7,454);
	CNeuron20.write(0,187);
	CNeuron20.write(1,305);
	CNeuron20.write(2,42);
	CNeuron20.write(3,248);
	CNeuron20.write(4,441);
	CNeuron20.write(5,286);
	CNeuron20.write(6,92);
	CNeuron20.write(7,164);
	CNeuron21.write(0,282);
	CNeuron21.write(1,452);
	CNeuron21.write(2,234);
	CNeuron21.write(3,328);
	CNeuron21.write(4,289);
	CNeuron21.write(5,273);
	CNeuron21.write(6,168);
	CNeuron21.write(7,272);
	CNeuron22.write(0,295);
	CNeuron22.write(1,112);
	CNeuron22.write(2,278);
	CNeuron22.write(3,463);
	CNeuron22.write(4,351);
	CNeuron22.write(5,55);
	CNeuron22.write(6,162);
	CNeuron22.write(7,451);
	CNeuron23.write(0,496);
	CNeuron23.write(1,302);
	CNeuron23.write(2,387);
	CNeuron23.write(3,262);
	CNeuron23.write(4,263);
	CNeuron23.write(5,120);
	CNeuron23.write(6,166);
	CNeuron23.write(7,270);
	CNeuron24.write(0,396);
	CNeuron24.write(1,366);
	CNeuron24.write(2,300);
	CNeuron24.write(3,287);
	CNeuron24.write(4,16);
	CNeuron24.write(5,437);
	CNeuron24.write(6,186);
	CNeuron24.write(7,15);
	CNeuron25.write(0,208);
	CNeuron25.write(1,60);
	CNeuron25.write(2,325);
	CNeuron25.write(3,189);
	CNeuron25.write(4,302);
	CNeuron25.write(5,139);
	CNeuron25.write(6,237);
	CNeuron25.write(7,51);
	CNeuron26.write(0,1);
	CNeuron26.write(1,417);
	CNeuron26.write(2,101);
	CNeuron26.write(3,475);
	CNeuron26.write(4,307);
	CNeuron26.write(5,284);
	CNeuron26.write(6,70);
	CNeuron26.write(7,246);
	CNeuron27.write(0,67);
	CNeuron27.write(1,374);
	CNeuron27.write(2,478);
	CNeuron27.write(3,104);
	CNeuron27.write(4,69);
	CNeuron27.write(5,431);
	CNeuron27.write(6,146);
	CNeuron27.write(7,253);
	CNeuron28.write(0,459);
	CNeuron28.write(1,354);
	CNeuron28.write(2,135);
	CNeuron28.write(3,116);
	CNeuron28.write(4,74);
	CNeuron28.write(5,233);
	CNeuron28.write(6,378);
	CNeuron28.write(7,367);
	CNeuron29.write(0,113);
	CNeuron29.write(1,244);
	CNeuron29.write(2,176);
	CNeuron29.write(3,185);
	CNeuron29.write(4,480);
	CNeuron29.write(5,505);
	CNeuron29.write(6,381);
	CNeuron29.write(7,282);
	CNeuron30.write(0,418);
	CNeuron30.write(1,335);
	CNeuron30.write(2,361);
	CNeuron30.write(3,264);
	CNeuron30.write(4,59);
	CNeuron30.write(5,223);
	CNeuron30.write(6,372);
	CNeuron30.write(7,305);
	CNeuron31.write(0,120);
	CNeuron31.write(1,404);
	CNeuron31.write(2,64);
	CNeuron31.write(3,31);
	CNeuron31.write(4,316);
	CNeuron31.write(5,20);
	CNeuron31.write(6,294);
	CNeuron31.write(7,318);
	CNeuron32.write(0,273);
	CNeuron32.write(1,415);
	CNeuron32.write(2,425);
	CNeuron32.write(3,77);
	CNeuron32.write(4,494);
	CNeuron32.write(5,304);
	CNeuron32.write(6,1);
	CNeuron32.write(7,458);
	CNeuron33.write(0,347);
	CNeuron33.write(1,488);
	CNeuron33.write(2,497);
	CNeuron33.write(3,2);
	CNeuron33.write(4,487);
	CNeuron33.write(5,427);
	CNeuron33.write(6,346);
	CNeuron33.write(7,182);
	CNeuron34.write(0,299);
	CNeuron34.write(1,198);
	CNeuron34.write(2,194);
	CNeuron34.write(3,428);
	CNeuron34.write(4,211);
	CNeuron34.write(5,147);
	CNeuron34.write(6,306);
	CNeuron34.write(7,13);
	CNeuron35.write(0,233);
	CNeuron35.write(1,447);
	CNeuron35.write(2,385);
	CNeuron35.write(3,189);
	CNeuron35.write(4,184);
	CNeuron35.write(5,428);
	CNeuron35.write(6,263);
	CNeuron35.write(7,120);
	CNeuron36.write(0,420);
	CNeuron36.write(1,400);
	CNeuron36.write(2,383);
	CNeuron36.write(3,107);
	CNeuron36.write(4,354);
	CNeuron36.write(5,91);
	CNeuron36.write(6,143);
	CNeuron36.write(7,89);
	CNeuron37.write(0,415);
	CNeuron37.write(1,123);
	CNeuron37.write(2,507);
	CNeuron37.write(3,284);
	CNeuron37.write(4,307);
	CNeuron37.write(5,372);
	CNeuron37.write(6,203);
	CNeuron37.write(7,297);
	CNeuron38.write(0,478);
	CNeuron38.write(1,417);
	CNeuron38.write(2,272);
	CNeuron38.write(3,33);
	CNeuron38.write(4,291);
	CNeuron38.write(5,343);
	CNeuron38.write(6,348);
	CNeuron38.write(7,440);
	CNeuron39.write(0,225);
	CNeuron39.write(1,278);
	CNeuron39.write(2,325);
	CNeuron39.write(3,189);
	CNeuron39.write(4,292);
	CNeuron39.write(5,463);
	CNeuron39.write(6,211);
	CNeuron39.write(7,5);
	CNeuron40.write(0,470);
	CNeuron40.write(1,425);
	CNeuron40.write(2,460);
	CNeuron40.write(3,49);
	CNeuron40.write(4,105);
	CNeuron40.write(5,379);
	CNeuron40.write(6,325);
	CNeuron40.write(7,333);
	CNeuron41.write(0,208);
	CNeuron41.write(1,327);
	CNeuron41.write(2,99);
	CNeuron41.write(3,198);
	CNeuron41.write(4,76);
	CNeuron41.write(5,442);
	CNeuron41.write(6,312);
	CNeuron41.write(7,396);
	CNeuron42.write(0,137);
	CNeuron42.write(1,28);
	CNeuron42.write(2,395);
	CNeuron42.write(3,343);
	CNeuron42.write(4,428);
	CNeuron42.write(5,117);
	CNeuron42.write(6,324);
	CNeuron42.write(7,20);
	CNeuron43.write(0,236);
	CNeuron43.write(1,132);
	CNeuron43.write(2,488);
	CNeuron43.write(3,349);
	CNeuron43.write(4,227);
	CNeuron43.write(5,180);
	CNeuron43.write(6,91);
	CNeuron43.write(7,442);
	CNeuron44.write(0,44);
	CNeuron44.write(1,13);
	CNeuron44.write(2,320);
	CNeuron44.write(3,441);
	CNeuron44.write(4,196);
	CNeuron44.write(5,135);
	CNeuron44.write(6,270);
	CNeuron44.write(7,299);
	CNeuron45.write(0,431);
	CNeuron45.write(1,113);
	CNeuron45.write(2,92);
	CNeuron45.write(3,159);
	CNeuron45.write(4,165);
	CNeuron45.write(5,485);
	CNeuron45.write(6,457);
	CNeuron45.write(7,464);
	CNeuron46.write(0,132);
	CNeuron46.write(1,475);
	CNeuron46.write(2,333);
	CNeuron46.write(3,180);
	CNeuron46.write(4,132);
	CNeuron46.write(5,77);
	CNeuron46.write(6,327);
	CNeuron46.write(7,121);
	CNeuron47.write(0,477);
	CNeuron47.write(1,488);
	CNeuron47.write(2,390);
	CNeuron47.write(3,393);
	CNeuron47.write(4,247);
	CNeuron47.write(5,15);
	CNeuron47.write(6,477);
	CNeuron47.write(7,386);
	CNeuron48.write(0,48);
	CNeuron48.write(1,109);
	CNeuron48.write(2,290);
	CNeuron48.write(3,322);
	CNeuron48.write(4,154);
	CNeuron48.write(5,505);
	CNeuron48.write(6,478);
	CNeuron48.write(7,356);
	CNeuron49.write(0,300);
	CNeuron49.write(1,373);
	CNeuron49.write(2,463);
	CNeuron49.write(3,254);
	CNeuron49.write(4,454);
	CNeuron49.write(5,213);
	CNeuron49.write(6,328);
	CNeuron49.write(7,137);
	CNeuron50.write(0,348);
	CNeuron50.write(1,22);
	CNeuron50.write(2,294);
	CNeuron50.write(3,448);
	CNeuron50.write(4,100);
	CNeuron50.write(5,329);
	CNeuron50.write(6,278);
	CNeuron50.write(7,463);
	CNeuron51.write(0,502);
	CNeuron51.write(1,165);
	CNeuron51.write(2,99);
	CNeuron51.write(3,498);
	CNeuron51.write(4,66);
	CNeuron51.write(5,93);
	CNeuron51.write(6,324);
	CNeuron51.write(7,45);
	CNeuron52.write(0,194);
	CNeuron52.write(1,365);
	CNeuron52.write(2,10);
	CNeuron52.write(3,329);
	CNeuron52.write(4,429);
	CNeuron52.write(5,211);
	CNeuron52.write(6,76);
	CNeuron52.write(7,115);
	CNeuron53.write(0,222);
	CNeuron53.write(1,70);
	CNeuron53.write(2,175);
	CNeuron53.write(3,333);
	CNeuron53.write(4,284);
	CNeuron53.write(5,439);
	CNeuron53.write(6,249);
	CNeuron53.write(7,276);
	CNeuron54.write(0,35);
	CNeuron54.write(1,311);
	CNeuron54.write(2,376);
	CNeuron54.write(3,255);
	CNeuron54.write(4,386);
	CNeuron54.write(5,92);
	CNeuron54.write(6,155);
	CNeuron54.write(7,317);
	CNeuron55.write(0,276);
	CNeuron55.write(1,9);
	CNeuron55.write(2,319);
	CNeuron55.write(3,269);
	CNeuron55.write(4,166);
	CNeuron55.write(5,357);
	CNeuron55.write(6,346);
	CNeuron55.write(7,78);
	CNeuron56.write(0,49);
	CNeuron56.write(1,506);
	CNeuron56.write(2,243);
	CNeuron56.write(3,502);
	CNeuron56.write(4,137);
	CNeuron56.write(5,494);
	CNeuron56.write(6,83);
	CNeuron56.write(7,304);
	CNeuron57.write(0,465);
	CNeuron57.write(1,431);
	CNeuron57.write(2,127);
	CNeuron57.write(3,118);
	CNeuron57.write(4,259);
	CNeuron57.write(5,471);
	CNeuron57.write(6,266);
	CNeuron57.write(7,384);
	CNeuron58.write(0,440);
	CNeuron58.write(1,246);
	CNeuron58.write(2,506);
	CNeuron58.write(3,403);
	CNeuron58.write(4,116);
	CNeuron58.write(5,409);
	CNeuron58.write(6,368);
	CNeuron58.write(7,30);
	CNeuron59.write(0,13);
	CNeuron59.write(1,423);
	CNeuron59.write(2,38);
	CNeuron59.write(3,155);
	CNeuron59.write(4,409);
	CNeuron59.write(5,216);
	CNeuron59.write(6,457);
	CNeuron59.write(7,175);
	CNeuron60.write(0,387);
	CNeuron60.write(1,379);
	CNeuron60.write(2,87);
	CNeuron60.write(3,180);
	CNeuron60.write(4,282);
	CNeuron60.write(5,443);
	CNeuron60.write(6,314);
	CNeuron60.write(7,32);
	CNeuron61.write(0,42);
	CNeuron61.write(1,262);
	CNeuron61.write(2,35);
	CNeuron61.write(3,364);
	CNeuron61.write(4,89);
	CNeuron61.write(5,424);
	CNeuron61.write(6,152);
	CNeuron61.write(7,118);
	CNeuron62.write(0,273);
	CNeuron62.write(1,287);
	CNeuron62.write(2,258);
	CNeuron62.write(3,361);
	CNeuron62.write(4,429);
	CNeuron62.write(5,68);
	CNeuron62.write(6,382);
	CNeuron62.write(7,417);
	CNeuron63.write(0,138);
	CNeuron63.write(1,475);
	CNeuron63.write(2,410);
	CNeuron63.write(3,98);
	CNeuron63.write(4,208);
	CNeuron63.write(5,41);
	CNeuron63.write(6,29);
	CNeuron63.write(7,451);
	CNeuron64.write(0,351);
	CNeuron64.write(1,50);
	CNeuron64.write(2,372);
	CNeuron64.write(3,293);
	CNeuron64.write(4,334);
	CNeuron64.write(5,39);
	CNeuron64.write(6,66);
	CNeuron64.write(7,197);


	if (flag==0) {
		CNeuronRes1.read(temp_holder,0);			//check which neuron to calculate. if 1st packet, neuron 1, if 2nd, neuron 2 and so on
		CNeuron1.read(temp_weight1,0);
		CNeuron1.read(temp_weight2,1);
		CNeuron1.read(temp_weight3,2);
		CNeuron1.read(temp_weight4,3);
		CNeuron1.read(temp_weight5,4);
		CNeuron1.read(temp_weight6,5);
		CNeuron1.read(temp_weight7,6);
		CNeuron1.read(temp_weight8,7);
	}
	else if (flag==1) {
		CNeuronRes2.read(temp_holder,0);
		CNeuron2.read(temp_weight1,0);
		CNeuron2.read(temp_weight2,1);
		CNeuron2.read(temp_weight3,2);
		CNeuron2.read(temp_weight4,3);
		CNeuron2.read(temp_weight5,4);
		CNeuron2.read(temp_weight6,5);
		CNeuron2.read(temp_weight7,6);
		CNeuron2.read(temp_weight8,7);
	}
	else if (flag==2) {
		CNeuronRes3.read(temp_holder,0);
		CNeuron3.read(temp_weight1,0);
		CNeuron3.read(temp_weight2,1);
		CNeuron3.read(temp_weight3,2);
		CNeuron3.read(temp_weight4,3);
		CNeuron3.read(temp_weight5,4);
		CNeuron3.read(temp_weight6,5);
		CNeuron3.read(temp_weight7,6);
		CNeuron3.read(temp_weight8,7);
	}
	else if (flag==3) {
		CNeuronRes4.read(temp_holder,0);
		CNeuron4.read(temp_weight1,0);
		CNeuron4.read(temp_weight2,1);
		CNeuron4.read(temp_weight3,2);
		CNeuron4.read(temp_weight4,3);
		CNeuron4.read(temp_weight5,4);
		CNeuron4.read(temp_weight6,5);
		CNeuron4.read(temp_weight7,6);
		CNeuron4.read(temp_weight8,7);
	}
	else if (flag==4) {
		CNeuronRes5.read(temp_holder,0);
		CNeuron5.read(temp_weight1,0);
		CNeuron5.read(temp_weight2,1);
		CNeuron5.read(temp_weight3,2);
		CNeuron5.read(temp_weight4,3);
		CNeuron5.read(temp_weight5,4);
		CNeuron5.read(temp_weight6,5);
		CNeuron5.read(temp_weight7,6);
		CNeuron5.read(temp_weight8,7);
	}
	else if (flag==5) {
		CNeuronRes6.read(temp_holder,0);
		CNeuron6.read(temp_weight1,0);
		CNeuron6.read(temp_weight2,1);
		CNeuron6.read(temp_weight3,2);
		CNeuron6.read(temp_weight4,3);
		CNeuron6.read(temp_weight5,4);
		CNeuron6.read(temp_weight6,5);
		CNeuron6.read(temp_weight7,6);
		CNeuron6.read(temp_weight8,7);
	}
	else if (flag==6) {
		CNeuronRes7.read(temp_holder,0);
		CNeuron7.read(temp_weight1,0);
		CNeuron7.read(temp_weight2,1);
		CNeuron7.read(temp_weight3,2);
		CNeuron7.read(temp_weight4,3);
		CNeuron7.read(temp_weight5,4);
		CNeuron7.read(temp_weight6,5);
		CNeuron7.read(temp_weight7,6);
		CNeuron7.read(temp_weight8,7);
	}
	else if (flag==7) {
		CNeuronRes8.read(temp_holder,0);
		CNeuron8.read(temp_weight1,0);
		CNeuron8.read(temp_weight2,1);
		CNeuron8.read(temp_weight3,2);
		CNeuron8.read(temp_weight4,3);
		CNeuron8.read(temp_weight5,4);
		CNeuron8.read(temp_weight6,5);
		CNeuron8.read(temp_weight7,6);
		CNeuron8.read(temp_weight8,7);
	}
	else if (flag==8) {
		CNeuronRes9.read(temp_holder,0);
		CNeuron9.read(temp_weight1,0);
		CNeuron9.read(temp_weight2,1);
		CNeuron9.read(temp_weight3,2);
		CNeuron9.read(temp_weight4,3);
		CNeuron9.read(temp_weight5,4);
		CNeuron9.read(temp_weight6,5);
		CNeuron9.read(temp_weight7,6);
		CNeuron9.read(temp_weight8,7);
	}
	else if (flag==9) {
		CNeuronRes10.read(temp_holder,0);
		CNeuron10.read(temp_weight1,0);
		CNeuron10.read(temp_weight2,1);
		CNeuron10.read(temp_weight3,2);
		CNeuron10.read(temp_weight4,3);
		CNeuron10.read(temp_weight5,4);
		CNeuron10.read(temp_weight6,5);
		CNeuron10.read(temp_weight7,6);
		CNeuron10.read(temp_weight8,7);
	}
	else if (flag==10) {
		CNeuronRes11.read(temp_holder,0);
		CNeuron11.read(temp_weight1,0);
		CNeuron11.read(temp_weight2,1);
		CNeuron11.read(temp_weight3,2);
		CNeuron11.read(temp_weight4,3);
		CNeuron11.read(temp_weight5,4);
		CNeuron11.read(temp_weight6,5);
		CNeuron11.read(temp_weight7,6);
		CNeuron11.read(temp_weight8,7);
	}
	else if (flag==11) {
		CNeuronRes12.read(temp_holder,0);
		CNeuron12.read(temp_weight1,0);
		CNeuron12.read(temp_weight2,1);
		CNeuron12.read(temp_weight3,2);
		CNeuron12.read(temp_weight4,3);
		CNeuron12.read(temp_weight5,4);
		CNeuron12.read(temp_weight6,5);
		CNeuron12.read(temp_weight7,6);
		CNeuron12.read(temp_weight8,7);
	}
	else if (flag==12) {
		CNeuronRes13.read(temp_holder,0);
		CNeuron13.read(temp_weight1,0);
		CNeuron13.read(temp_weight2,1);
		CNeuron13.read(temp_weight3,2);
		CNeuron13.read(temp_weight4,3);
		CNeuron13.read(temp_weight5,4);
		CNeuron13.read(temp_weight6,5);
		CNeuron13.read(temp_weight7,6);
		CNeuron13.read(temp_weight8,7);
	}
	else if (flag==13) {
		CNeuronRes14.read(temp_holder,0);
		CNeuron14.read(temp_weight1,0);
		CNeuron14.read(temp_weight2,1);
		CNeuron14.read(temp_weight3,2);
		CNeuron14.read(temp_weight4,3);
		CNeuron14.read(temp_weight5,4);
		CNeuron14.read(temp_weight6,5);
		CNeuron14.read(temp_weight7,6);
		CNeuron14.read(temp_weight8,7);
	}
	else if (flag==14) {
		CNeuronRes15.read(temp_holder,0);
		CNeuron15.read(temp_weight1,0);
		CNeuron15.read(temp_weight2,1);
		CNeuron15.read(temp_weight3,2);
		CNeuron15.read(temp_weight4,3);
		CNeuron15.read(temp_weight5,4);
		CNeuron15.read(temp_weight6,5);
		CNeuron15.read(temp_weight7,6);
		CNeuron15.read(temp_weight8,7);
	}
	else if (flag==15) {
		CNeuronRes16.read(temp_holder,0);
		CNeuron16.read(temp_weight1,0);
		CNeuron16.read(temp_weight2,1);
		CNeuron16.read(temp_weight3,2);
		CNeuron16.read(temp_weight4,3);
		CNeuron16.read(temp_weight5,4);
		CNeuron16.read(temp_weight6,5);
		CNeuron16.read(temp_weight7,6);
		CNeuron16.read(temp_weight8,7);
	}
	else if (flag==16) {
		CNeuronRes17.read(temp_holder,0);
		CNeuron17.read(temp_weight1,0);
		CNeuron17.read(temp_weight2,1);
		CNeuron17.read(temp_weight3,2);
		CNeuron17.read(temp_weight4,3);
		CNeuron17.read(temp_weight5,4);
		CNeuron17.read(temp_weight6,5);
		CNeuron17.read(temp_weight7,6);
		CNeuron17.read(temp_weight8,7);
	}
	else if (flag==17) {
		CNeuronRes18.read(temp_holder,0);
		CNeuron18.read(temp_weight1,0);
		CNeuron18.read(temp_weight2,1);
		CNeuron18.read(temp_weight3,2);
		CNeuron18.read(temp_weight4,3);
		CNeuron18.read(temp_weight5,4);
		CNeuron18.read(temp_weight6,5);
		CNeuron18.read(temp_weight7,6);
		CNeuron18.read(temp_weight8,7);
	}
	else if (flag==18) {
		CNeuronRes19.read(temp_holder,0);
		CNeuron19.read(temp_weight1,0);
		CNeuron19.read(temp_weight2,1);
		CNeuron19.read(temp_weight3,2);
		CNeuron19.read(temp_weight4,3);
		CNeuron19.read(temp_weight5,4);
		CNeuron19.read(temp_weight6,5);
		CNeuron19.read(temp_weight7,6);
		CNeuron19.read(temp_weight8,7);
	}
	else if (flag==19) {
		CNeuronRes20.read(temp_holder,0);
		CNeuron20.read(temp_weight1,0);
		CNeuron20.read(temp_weight2,1);
		CNeuron20.read(temp_weight3,2);
		CNeuron20.read(temp_weight4,3);
		CNeuron20.read(temp_weight5,4);
		CNeuron20.read(temp_weight6,5);
		CNeuron20.read(temp_weight7,6);
		CNeuron20.read(temp_weight8,7);
	}
	else if (flag==20) {
		CNeuronRes21.read(temp_holder,0);
		CNeuron21.read(temp_weight1,0);
		CNeuron21.read(temp_weight2,1);
		CNeuron21.read(temp_weight3,2);
		CNeuron21.read(temp_weight4,3);
		CNeuron21.read(temp_weight5,4);
		CNeuron21.read(temp_weight6,5);
		CNeuron21.read(temp_weight7,6);
		CNeuron21.read(temp_weight8,7);
	}
	else if (flag==21) {
		CNeuronRes22.read(temp_holder,0);
		CNeuron22.read(temp_weight1,0);
		CNeuron22.read(temp_weight2,1);
		CNeuron22.read(temp_weight3,2);
		CNeuron22.read(temp_weight4,3);
		CNeuron22.read(temp_weight5,4);
		CNeuron22.read(temp_weight6,5);
		CNeuron22.read(temp_weight7,6);
		CNeuron22.read(temp_weight8,7);
	}
	else if (flag==22) {
		CNeuronRes23.read(temp_holder,0);
		CNeuron23.read(temp_weight1,0);
		CNeuron23.read(temp_weight2,1);
		CNeuron23.read(temp_weight3,2);
		CNeuron23.read(temp_weight4,3);
		CNeuron23.read(temp_weight5,4);
		CNeuron23.read(temp_weight6,5);
		CNeuron23.read(temp_weight7,6);
		CNeuron23.read(temp_weight8,7);
	}
	else if (flag==23) {
		CNeuronRes24.read(temp_holder,0);
		CNeuron24.read(temp_weight1,0);
		CNeuron24.read(temp_weight2,1);
		CNeuron24.read(temp_weight3,2);
		CNeuron24.read(temp_weight4,3);
		CNeuron24.read(temp_weight5,4);
		CNeuron24.read(temp_weight6,5);
		CNeuron24.read(temp_weight7,6);
		CNeuron24.read(temp_weight8,7);
	}
	else if (flag==24) {
		CNeuronRes25.read(temp_holder,0);
		CNeuron25.read(temp_weight1,0);
		CNeuron25.read(temp_weight2,1);
		CNeuron25.read(temp_weight3,2);
		CNeuron25.read(temp_weight4,3);
		CNeuron25.read(temp_weight5,4);
		CNeuron25.read(temp_weight6,5);
		CNeuron25.read(temp_weight7,6);
		CNeuron25.read(temp_weight8,7);
	}
	else if (flag==25) {
		CNeuronRes26.read(temp_holder,0);
		CNeuron26.read(temp_weight1,0);
		CNeuron26.read(temp_weight2,1);
		CNeuron26.read(temp_weight3,2);
		CNeuron26.read(temp_weight4,3);
		CNeuron26.read(temp_weight5,4);
		CNeuron26.read(temp_weight6,5);
		CNeuron26.read(temp_weight7,6);
		CNeuron26.read(temp_weight8,7);
	}
	else if (flag==26) {
		CNeuronRes27.read(temp_holder,0);
		CNeuron27.read(temp_weight1,0);
		CNeuron27.read(temp_weight2,1);
		CNeuron27.read(temp_weight3,2);
		CNeuron27.read(temp_weight4,3);
		CNeuron27.read(temp_weight5,4);
		CNeuron27.read(temp_weight6,5);
		CNeuron27.read(temp_weight7,6);
		CNeuron27.read(temp_weight8,7);
	}
	else if (flag==27) {
		CNeuronRes28.read(temp_holder,0);
		CNeuron28.read(temp_weight1,0);
		CNeuron28.read(temp_weight2,1);
		CNeuron28.read(temp_weight3,2);
		CNeuron28.read(temp_weight4,3);
		CNeuron28.read(temp_weight5,4);
		CNeuron28.read(temp_weight6,5);
		CNeuron28.read(temp_weight7,6);
		CNeuron28.read(temp_weight8,7);
	}
	else if (flag==28) {
		CNeuronRes29.read(temp_holder,0);
		CNeuron29.read(temp_weight1,0);
		CNeuron29.read(temp_weight2,1);
		CNeuron29.read(temp_weight3,2);
		CNeuron29.read(temp_weight4,3);
		CNeuron29.read(temp_weight5,4);
		CNeuron29.read(temp_weight6,5);
		CNeuron29.read(temp_weight7,6);
		CNeuron29.read(temp_weight8,7);
	}
	else if (flag==29) {
		CNeuronRes30.read(temp_holder,0);
		CNeuron30.read(temp_weight1,0);
		CNeuron30.read(temp_weight2,1);
		CNeuron30.read(temp_weight3,2);
		CNeuron30.read(temp_weight4,3);
		CNeuron30.read(temp_weight5,4);
		CNeuron30.read(temp_weight6,5);
		CNeuron30.read(temp_weight7,6);
		CNeuron30.read(temp_weight8,7);
	}
	else if (flag==30) {
		CNeuronRes31.read(temp_holder,0);
		CNeuron31.read(temp_weight1,0);
		CNeuron31.read(temp_weight2,1);
		CNeuron31.read(temp_weight3,2);
		CNeuron31.read(temp_weight4,3);
		CNeuron31.read(temp_weight5,4);
		CNeuron31.read(temp_weight6,5);
		CNeuron31.read(temp_weight7,6);
		CNeuron31.read(temp_weight8,7);
	}
	else if (flag==31) {
		CNeuronRes32.read(temp_holder,0);
		CNeuron32.read(temp_weight1,0);
		CNeuron32.read(temp_weight2,1);
		CNeuron32.read(temp_weight3,2);
		CNeuron32.read(temp_weight4,3);
		CNeuron32.read(temp_weight5,4);
		CNeuron32.read(temp_weight6,5);
		CNeuron32.read(temp_weight7,6);
		CNeuron32.read(temp_weight8,7);
	}
	else if (flag==32) {
		CNeuronRes33.read(temp_holder,0);
		CNeuron33.read(temp_weight1,0);
		CNeuron33.read(temp_weight2,1);
		CNeuron33.read(temp_weight3,2);
		CNeuron33.read(temp_weight4,3);
		CNeuron33.read(temp_weight5,4);
		CNeuron33.read(temp_weight6,5);
		CNeuron33.read(temp_weight7,6);
		CNeuron33.read(temp_weight8,7);
	}
	else if (flag==33) {
		CNeuronRes34.read(temp_holder,0);
		CNeuron34.read(temp_weight1,0);
		CNeuron34.read(temp_weight2,1);
		CNeuron34.read(temp_weight3,2);
		CNeuron34.read(temp_weight4,3);
		CNeuron34.read(temp_weight5,4);
		CNeuron34.read(temp_weight6,5);
		CNeuron34.read(temp_weight7,6);
		CNeuron34.read(temp_weight8,7);
	}
	else if (flag==34) {
		CNeuronRes35.read(temp_holder,0);
		CNeuron35.read(temp_weight1,0);
		CNeuron35.read(temp_weight2,1);
		CNeuron35.read(temp_weight3,2);
		CNeuron35.read(temp_weight4,3);
		CNeuron35.read(temp_weight5,4);
		CNeuron35.read(temp_weight6,5);
		CNeuron35.read(temp_weight7,6);
		CNeuron35.read(temp_weight8,7);
	}
	else if (flag==35) {
		CNeuronRes36.read(temp_holder,0);
		CNeuron36.read(temp_weight1,0);
		CNeuron36.read(temp_weight2,1);
		CNeuron36.read(temp_weight3,2);
		CNeuron36.read(temp_weight4,3);
		CNeuron36.read(temp_weight5,4);
		CNeuron36.read(temp_weight6,5);
		CNeuron36.read(temp_weight7,6);
		CNeuron36.read(temp_weight8,7);
	}
	else if (flag==36) {
		CNeuronRes37.read(temp_holder,0);
		CNeuron37.read(temp_weight1,0);
		CNeuron37.read(temp_weight2,1);
		CNeuron37.read(temp_weight3,2);
		CNeuron37.read(temp_weight4,3);
		CNeuron37.read(temp_weight5,4);
		CNeuron37.read(temp_weight6,5);
		CNeuron37.read(temp_weight7,6);
		CNeuron37.read(temp_weight8,7);
	}
	else if (flag==37) {
	
		CNeuronRes38.read(temp_holder,0);
		CNeuron38.read(temp_weight1,0);
		CNeuron38.read(temp_weight2,1);
		CNeuron38.read(temp_weight3,2);
		CNeuron38.read(temp_weight4,3);
		CNeuron38.read(temp_weight5,4);
		CNeuron38.read(temp_weight6,5);
		CNeuron38.read(temp_weight7,6);
		CNeuron38.read(temp_weight8,7);
	}
	else if (flag==38) {
		CNeuronRes39.read(temp_holder,0);
		CNeuron39.read(temp_weight1,0);
		CNeuron39.read(temp_weight2,1);
		CNeuron39.read(temp_weight3,2);
		CNeuron39.read(temp_weight4,3);
		CNeuron39.read(temp_weight5,4);
		CNeuron39.read(temp_weight6,5);
		CNeuron39.read(temp_weight7,6);
		CNeuron39.read(temp_weight8,7);
	}
	else if (flag==39) {
		CNeuronRes40.read(temp_holder,0);
		CNeuron40.read(temp_weight1,0);
		CNeuron40.read(temp_weight2,1);
		CNeuron40.read(temp_weight3,2);
		CNeuron40.read(temp_weight4,3);
		CNeuron40.read(temp_weight5,4);
		CNeuron40.read(temp_weight6,5);
		CNeuron40.read(temp_weight7,6);
		CNeuron40.read(temp_weight8,7);
	}
	else if (flag==40) {
		CNeuronRes41.read(temp_holder,0);
		CNeuron41.read(temp_weight1,0);
		CNeuron41.read(temp_weight2,1);
		CNeuron41.read(temp_weight3,2);
		CNeuron41.read(temp_weight4,3);
		CNeuron41.read(temp_weight5,4);
		CNeuron41.read(temp_weight6,5);
		CNeuron41.read(temp_weight7,6);
		CNeuron41.read(temp_weight8,7);
	}
	else if (flag==41) {
		CNeuronRes42.read(temp_holder,0);
		CNeuron42.read(temp_weight1,0);
		CNeuron42.read(temp_weight2,1);
		CNeuron42.read(temp_weight3,2);
		CNeuron42.read(temp_weight4,3);
		CNeuron42.read(temp_weight5,4);
		CNeuron42.read(temp_weight6,5);
		CNeuron42.read(temp_weight7,6);
		CNeuron42.read(temp_weight8,7);
	}
	else if (flag==42) {
		CNeuronRes43.read(temp_holder,0);
		CNeuron43.read(temp_weight1,0);
		CNeuron43.read(temp_weight2,1);
		CNeuron43.read(temp_weight3,2);
		CNeuron43.read(temp_weight4,3);
		CNeuron43.read(temp_weight5,4);
		CNeuron43.read(temp_weight6,5);
		CNeuron43.read(temp_weight7,6);
		CNeuron43.read(temp_weight8,7);
	}
	else if (flag==43) {
		CNeuronRes44.read(temp_holder,0);
		CNeuron44.read(temp_weight1,0);
		CNeuron44.read(temp_weight2,1);
		CNeuron44.read(temp_weight3,2);
		CNeuron44.read(temp_weight4,3);
		CNeuron44.read(temp_weight5,4);
		CNeuron44.read(temp_weight6,5);
		CNeuron44.read(temp_weight7,6);
		CNeuron44.read(temp_weight8,7);
	}
	else if (flag==44) {
		CNeuronRes45.read(temp_holder,0);
		CNeuron45.read(temp_weight1,0);
		CNeuron45.read(temp_weight2,1);
		CNeuron45.read(temp_weight3,2);
		CNeuron45.read(temp_weight4,3);
		CNeuron45.read(temp_weight5,4);
		CNeuron45.read(temp_weight6,5);
		CNeuron45.read(temp_weight7,6);
		CNeuron45.read(temp_weight8,7);
	}
	else if (flag==45) {
		CNeuronRes46.read(temp_holder,0);
		CNeuron46.read(temp_weight1,0);
		CNeuron46.read(temp_weight2,1);
		CNeuron46.read(temp_weight3,2);
		CNeuron46.read(temp_weight4,3);
		CNeuron46.read(temp_weight5,4);
		CNeuron46.read(temp_weight6,5);
		CNeuron46.read(temp_weight7,6);
		CNeuron46.read(temp_weight8,7);
	}
	else if (flag==46) {
		CNeuronRes47.read(temp_holder,0);
		CNeuron47.read(temp_weight1,0);
		CNeuron47.read(temp_weight2,1);
		CNeuron47.read(temp_weight3,2);
		CNeuron47.read(temp_weight4,3);
		CNeuron47.read(temp_weight5,4);
		CNeuron47.read(temp_weight6,5);
		CNeuron47.read(temp_weight7,6);
		CNeuron47.read(temp_weight8,7);
	}
	else if (flag==47) {
		CNeuronRes48.read(temp_holder,0);
		CNeuron48.read(temp_weight1,0);
		CNeuron48.read(temp_weight2,1);
		CNeuron48.read(temp_weight3,2);
		CNeuron48.read(temp_weight4,3);
		CNeuron48.read(temp_weight5,4);
		CNeuron48.read(temp_weight6,5);
		CNeuron48.read(temp_weight7,6);
		CNeuron48.read(temp_weight8,7);
	}
	else if (flag==48) {
		CNeuronRes49.read(temp_holder,0);
		CNeuron49.read(temp_weight1,0);
		CNeuron49.read(temp_weight2,1);
		CNeuron49.read(temp_weight3,2);
		CNeuron49.read(temp_weight4,3);
		CNeuron49.read(temp_weight5,4);
		CNeuron49.read(temp_weight6,5);
		CNeuron49.read(temp_weight7,6);
		CNeuron49.read(temp_weight8,7);
	}
	else if (flag==49) {
		CNeuronRes50.read(temp_holder,0);
		CNeuron50.read(temp_weight1,0);
		CNeuron50.read(temp_weight2,1);
		CNeuron50.read(temp_weight3,2);
		CNeuron50.read(temp_weight4,3);
		CNeuron50.read(temp_weight5,4);
		CNeuron50.read(temp_weight6,5);
		CNeuron50.read(temp_weight7,6);
		CNeuron50.read(temp_weight8,7);
	}
	else if (flag==50) {
		CNeuronRes51.read(temp_holder,0);
		CNeuron51.read(temp_weight1,0);
		CNeuron51.read(temp_weight2,1);
		CNeuron51.read(temp_weight3,2);
		CNeuron51.read(temp_weight4,3);
		CNeuron51.read(temp_weight5,4);
		CNeuron51.read(temp_weight6,5);
		CNeuron51.read(temp_weight7,6);
		CNeuron51.read(temp_weight8,7);
	}
	else if (flag==51) {
		CNeuronRes52.read(temp_holder,0);
		CNeuron52.read(temp_weight1,0);
		CNeuron52.read(temp_weight2,1);
		CNeuron52.read(temp_weight3,2);
		CNeuron52.read(temp_weight4,3);
		CNeuron52.read(temp_weight5,4);
		CNeuron52.read(temp_weight6,5);
		CNeuron52.read(temp_weight7,6);
		CNeuron52.read(temp_weight8,7);
	}
	else if (flag==52) {
		CNeuronRes53.read(temp_holder,0);
		CNeuron53.read(temp_weight1,0);
		CNeuron53.read(temp_weight2,1);
		CNeuron53.read(temp_weight3,2);
		CNeuron53.read(temp_weight4,3);
		CNeuron53.read(temp_weight5,4);
		CNeuron53.read(temp_weight6,5);
		CNeuron53.read(temp_weight7,6);
		CNeuron53.read(temp_weight8,7);
	}
	else if (flag==53) {
		CNeuronRes54.read(temp_holder,0);
		CNeuron54.read(temp_weight1,0);
		CNeuron54.read(temp_weight2,1);
		CNeuron54.read(temp_weight3,2);
		CNeuron54.read(temp_weight4,3);
		CNeuron54.read(temp_weight5,4);
		CNeuron54.read(temp_weight6,5);
		CNeuron54.read(temp_weight7,6);
		CNeuron54.read(temp_weight8,7);
	}
	else if (flag==54) {
		CNeuronRes55.read(temp_holder,0);
		CNeuron55.read(temp_weight1,0);
		CNeuron55.read(temp_weight2,1);
		CNeuron55.read(temp_weight3,2);
		CNeuron55.read(temp_weight4,3);
		CNeuron55.read(temp_weight5,4);
		CNeuron55.read(temp_weight6,5);
		CNeuron55.read(temp_weight7,6);
		CNeuron55.read(temp_weight8,7);
	}
	else if (flag==55) {
		CNeuronRes56.read(temp_holder,0);
		CNeuron56.read(temp_weight1,0);
		CNeuron56.read(temp_weight2,1);
		CNeuron56.read(temp_weight3,2);
		CNeuron56.read(temp_weight4,3);
		CNeuron56.read(temp_weight5,4);
		CNeuron56.read(temp_weight6,5);
		CNeuron56.read(temp_weight7,6);
		CNeuron56.read(temp_weight8,7);
	}
	else if (flag==56) {
		CNeuronRes57.read(temp_holder,0);
		CNeuron57.read(temp_weight1,0);
		CNeuron57.read(temp_weight2,1);
		CNeuron57.read(temp_weight3,2);
		CNeuron57.read(temp_weight4,3);
		CNeuron57.read(temp_weight5,4);
		CNeuron57.read(temp_weight6,5);
		CNeuron57.read(temp_weight7,6);
		CNeuron57.read(temp_weight8,7);
	}
	else if (flag==57) {
		CNeuronRes58.read(temp_holder,0);
		CNeuron58.read(temp_weight1,0);
		CNeuron58.read(temp_weight2,1);
		CNeuron58.read(temp_weight3,2);
		CNeuron58.read(temp_weight4,3);
		CNeuron58.read(temp_weight5,4);
		CNeuron58.read(temp_weight6,5);
		CNeuron58.read(temp_weight7,6);
		CNeuron58.read(temp_weight8,7);
	}
	else if (flag==58) {
		CNeuronRes59.read(temp_holder,0);
		CNeuron59.read(temp_weight1,0);
		CNeuron59.read(temp_weight2,1);
		CNeuron59.read(temp_weight3,2);
		CNeuron59.read(temp_weight4,3);
		CNeuron59.read(temp_weight5,4);
		CNeuron59.read(temp_weight6,5);
		CNeuron59.read(temp_weight7,6);
		CNeuron59.read(temp_weight8,7);
	}
	else if (flag==59) {
		CNeuronRes60.read(temp_holder,0);
		CNeuron60.read(temp_weight1,0);
		CNeuron60.read(temp_weight2,1);
		CNeuron60.read(temp_weight3,2);
		CNeuron60.read(temp_weight4,3);
		CNeuron60.read(temp_weight5,4);
		CNeuron60.read(temp_weight6,5);
		CNeuron60.read(temp_weight7,6);
		CNeuron60.read(temp_weight8,7);
	}
	else if (flag==60) {
		CNeuronRes61.read(temp_holder,0);
		CNeuron61.read(temp_weight1,0);
		CNeuron61.read(temp_weight2,1);
		CNeuron61.read(temp_weight3,2);
		CNeuron61.read(temp_weight4,3);
		CNeuron61.read(temp_weight5,4);
		CNeuron61.read(temp_weight6,5);
		CNeuron61.read(temp_weight7,6);
		CNeuron61.read(temp_weight8,7);
	}
	else if (flag==61) {
		CNeuronRes62.read(temp_holder,0);
		CNeuron62.read(temp_weight1,0);
		CNeuron62.read(temp_weight2,1);
		CNeuron62.read(temp_weight3,2);
		CNeuron62.read(temp_weight4,3);
		CNeuron62.read(temp_weight5,4);
		CNeuron62.read(temp_weight6,5);
		CNeuron62.read(temp_weight7,6);
		CNeuron62.read(temp_weight8,7);
	}
	else if (flag==62) {
		CNeuronRes63.read(temp_holder,0);
		CNeuron63.read(temp_weight1,0);
		CNeuron63.read(temp_weight2,1);
		CNeuron63.read(temp_weight3,2);
		CNeuron63.read(temp_weight4,3);
		CNeuron63.read(temp_weight5,4);
		CNeuron63.read(temp_weight6,5);
		CNeuron63.read(temp_weight7,6);
		CNeuron63.read(temp_weight8,7);
	}
	else if (flag==63) {
		CNeuronRes64.read(temp_holder,0);
		CNeuron64.read(temp_weight1,0);
		CNeuron64.read(temp_weight2,1);
		CNeuron64.read(temp_weight3,2);
		CNeuron64.read(temp_weight4,3);
		CNeuron64.read(temp_weight5,4);
		CNeuron64.read(temp_weight6,5);
		CNeuron64.read(temp_weight7,6);
		CNeuron64.read(temp_weight8,7);
	}


        temp_window=instr[168:168]++instr[167:167]++instr[166:166]++instr[165:165]++instr[164:164]++instr[155:155]++instr[154:154]++instr[153:153]++instr[152:152]++instr[151:151]++instr[142:142]++instr[141:141]++instr[140:140]++instr[139:139]++instr[138:138]++instr[129:129]++instr[128:128]++instr[127:127]++instr[126:126]++instr[125:125]++instr[116:116]++instr[115:115]++instr[114:114]++instr[113:113]++instr[112:112];
        CXNOR(temp_weight1,temp_window);				
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;			//take 5x5 window as kernel and use XNOR-popcount
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
        

        temp_window=instr[167:167]++instr[166:166]++instr[165:165]++instr[164:164]++instr[163:163]++instr[154:154]++instr[153:153]++instr[152:152]++instr[151:151]++instr[150:150]++instr[141:141]++instr[140:140]++instr[139:139]++instr[138:138]++instr[137:137]++instr[128:128]++instr[127:127]++instr[126:126]++instr[125:125]++instr[124:124]++instr[115:115]++instr[114:114]++instr[113:113]++instr[112:112]++instr[111:111];
        CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;

        temp_window=instr[166:166]++instr[165:165]++instr[164:164]++instr[163:163]++instr[162:162]++instr[153:153]++instr[152:152]++instr[151:151]++instr[150:150]++instr[149:149]++instr[140:140]++instr[139:139]++instr[138:138]++instr[137:137]++instr[136:136]++instr[127:127]++instr[126:126]++instr[125:125]++instr[124:124]++instr[123:123]++instr[114:114]++instr[113:113]++instr[112:112]++instr[111:111]++instr[110:110];
        CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[165:165]++instr[164:164]++instr[163:163]++instr[162:162]++instr[161:161]++instr[152:152]++instr[151:151]++instr[150:150]++instr[149:149]++instr[148:148]++instr[139:139]++instr[138:138]++instr[137:137]++instr[136:136]++instr[135:135]++instr[126:126]++instr[125:125]++instr[124:124]++instr[123:123]++instr[122:122]++instr[113:113]++instr[112:112]++instr[111:111]++instr[110:110]++instr[109:109];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[164:164]++instr[163:163]++instr[162:162]++instr[161:161]++instr[160:160]++instr[151:151]++instr[150:150]++instr[149:149]++instr[148:148]++instr[147:147]++instr[138:138]++instr[137:137]++instr[136:136]++instr[135:135]++instr[134:134]++instr[125:125]++instr[124:124]++instr[123:123]++instr[122:122]++instr[121:121]++instr[112:112]++instr[111:111]++instr[110:110]++instr[109:109]++instr[108:108];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[163:163]++instr[162:162]++instr[161:161]++instr[160:160]++instr[159:159]++instr[150:150]++instr[149:149]++instr[148:148]++instr[147:147]++instr[146:146]++instr[137:137]++instr[136:136]++instr[135:135]++instr[134:134]++instr[133:133]++instr[124:124]++instr[123:123]++instr[122:122]++instr[121:121]++instr[120:120]++instr[111:111]++instr[110:110]++instr[109:109]++instr[108:108]++instr[107:107];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[162:162]++instr[161:161]++instr[160:160]++instr[159:159]++instr[158:158]++instr[149:149]++instr[148:148]++instr[147:147]++instr[146:146]++instr[145:145]++instr[136:136]++instr[135:135]++instr[134:134]++instr[133:133]++instr[132:132]++instr[123:123]++instr[122:122]++instr[121:121]++instr[120:120]++instr[119:119]++instr[110:110]++instr[109:109]++instr[108:108]++instr[107:107]++instr[106:106];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[161:161]++instr[160:160]++instr[159:159]++instr[158:158]++instr[157:157]++instr[148:148]++instr[147:147]++instr[146:146]++instr[145:145]++instr[144:144]++instr[135:135]++instr[134:134]++instr[133:133]++instr[132:132]++instr[131:131]++instr[122:122]++instr[121:121]++instr[120:120]++instr[119:119]++instr[118:118]++instr[109:109]++instr[108:108]++instr[107:107]++instr[106:106]++instr[105:105];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[160:160]++instr[159:159]++instr[158:158]++instr[157:157]++instr[156:156]++instr[147:147]++instr[146:146]++instr[145:145]++instr[144:144]++instr[143:143]++instr[134:134]++instr[133:133]++instr[132:132]++instr[131:131]++instr[130:130]++instr[121:121]++instr[120:120]++instr[119:119]++instr[118:118]++instr[117:117]++instr[108:108]++instr[107:107]++instr[106:106]++instr[105:105]++instr[104:104];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[155:155]++instr[154:154]++instr[153:153]++instr[152:152]++instr[151:151]++instr[142:142]++instr[141:141]++instr[140:140]++instr[139:139]++instr[138:138]++instr[129:129]++instr[128:128]++instr[127:127]++instr[126:126]++instr[125:125]++instr[116:116]++instr[115:115]++instr[114:114]++instr[113:113]++instr[112:112]++instr[103:103]++instr[102:102]++instr[101:101]++instr[100:100]++instr[99:99];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[154:154]++instr[153:153]++instr[152:152]++instr[151:151]++instr[150:150]++instr[141:141]++instr[140:140]++instr[139:139]++instr[138:138]++instr[137:137]++instr[128:128]++instr[127:127]++instr[126:126]++instr[125:125]++instr[124:124]++instr[115:115]++instr[114:114]++instr[113:113]++instr[112:112]++instr[111:111]++instr[102:102]++instr[101:101]++instr[100:100]++instr[99:99]++instr[98:98];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[153:153]++instr[152:152]++instr[151:151]++instr[150:150]++instr[149:149]++instr[140:140]++instr[139:139]++instr[138:138]++instr[137:137]++instr[136:136]++instr[127:127]++instr[126:126]++instr[125:125]++instr[124:124]++instr[123:123]++instr[114:114]++instr[113:113]++instr[112:112]++instr[111:111]++instr[110:110]++instr[101:101]++instr[100:100]++instr[99:99]++instr[98:98]++instr[97:97];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[152:152]++instr[151:151]++instr[150:150]++instr[149:149]++instr[148:148]++instr[139:139]++instr[138:138]++instr[137:137]++instr[136:136]++instr[135:135]++instr[126:126]++instr[125:125]++instr[124:124]++instr[123:123]++instr[122:122]++instr[113:113]++instr[112:112]++instr[111:111]++instr[110:110]++instr[109:109]++instr[100:100]++instr[99:99]++instr[98:98]++instr[97:97]++instr[96:96];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		
		temp_window=instr[151:151]++instr[150:150]++instr[149:149]++instr[148:148]++instr[147:147]++instr[138:138]++instr[137:137]++instr[136:136]++instr[135:135]++instr[134:134]++instr[125:125]++instr[124:124]++instr[123:123]++instr[122:122]++instr[121:121]++instr[112:112]++instr[111:111]++instr[110:110]++instr[109:109]++instr[108:108]++instr[99:99]++instr[98:98]++instr[97:97]++instr[96:96]++instr[95:95];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[150:150]++instr[149:149]++instr[148:148]++instr[147:147]++instr[146:146]++instr[137:137]++instr[136:136]++instr[135:135]++instr[134:134]++instr[133:133]++instr[124:124]++instr[123:123]++instr[122:122]++instr[121:121]++instr[120:120]++instr[111:111]++instr[110:110]++instr[109:109]++instr[108:108]++instr[107:107]++instr[98:98]++instr[97:97]++instr[96:96]++instr[95:95]++instr[94:94];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		
		temp_window=instr[149:149]++instr[148:148]++instr[147:147]++instr[146:146]++instr[145:145]++instr[136:136]++instr[135:135]++instr[134:134]++instr[133:133]++instr[132:132]++instr[123:123]++instr[122:122]++instr[121:121]++instr[120:120]++instr[119:119]++instr[110:110]++instr[109:109]++instr[108:108]++instr[107:107]++instr[106:106]++instr[97:97]++instr[96:96]++instr[95:95]++instr[94:94]++instr[93:93];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		
		temp_window=instr[148:148]++instr[147:147]++instr[146:146]++instr[145:145]++instr[144:144]++instr[135:135]++instr[134:134]++instr[133:133]++instr[132:132]++instr[131:131]++instr[122:122]++instr[121:121]++instr[120:120]++instr[119:119]++instr[118:118]++instr[109:109]++instr[108:108]++instr[107:107]++instr[106:106]++instr[105:105]++instr[96:96]++instr[95:95]++instr[94:94]++instr[93:93]++instr[92:92];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		
		temp_window=instr[147:147]++instr[146:146]++instr[145:145]++instr[144:144]++instr[143:143]++instr[134:134]++instr[133:133]++instr[132:132]++instr[131:131]++instr[130:130]++instr[121:121]++instr[120:120]++instr[119:119]++instr[118:118]++instr[117:117]++instr[108:108]++instr[107:107]++instr[106:106]++instr[105:105]++instr[104:104]++instr[95:95]++instr[94:94]++instr[93:93]++instr[92:92]++instr[91:91];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[141:141]++instr[140:140]++instr[139:139]++instr[138:138]++instr[137:137]++instr[128:128]++instr[127:127]++instr[126:126]++instr[125:125]++instr[124:124]++instr[115:115]++instr[114:114]++instr[113:113]++instr[112:112]++instr[111:111]++instr[102:102]++instr[101:101]++instr[100:100]++instr[99:99]++instr[98:98]++instr[89:89]++instr[88:88]++instr[87:87]++instr[86:86]++instr[85:85];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		
		temp_window=instr[140:140]++instr[139:139]++instr[138:138]++instr[137:137]++instr[136:136]++instr[127:127]++instr[126:126]++instr[125:125]++instr[124:124]++instr[123:123]++instr[114:114]++instr[113:113]++instr[112:112]++instr[111:111]++instr[110:110]++instr[101:101]++instr[100:100]++instr[99:99]++instr[98:98]++instr[97:97]++instr[88:88]++instr[87:87]++instr[86:86]++instr[85:85]++instr[84:84];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		
		temp_window=instr[139:139]++instr[138:138]++instr[137:137]++instr[136:136]++instr[135:135]++instr[126:126]++instr[125:125]++instr[124:124]++instr[123:123]++instr[122:122]++instr[113:113]++instr[112:112]++instr[111:111]++instr[110:110]++instr[109:109]++instr[100:100]++instr[99:99]++instr[98:98]++instr[97:97]++instr[96:96]++instr[87:87]++instr[86:86]++instr[85:85]++instr[84:84]++instr[83:83];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		
		temp_window=instr[138:138]++instr[137:137]++instr[136:136]++instr[135:135]++instr[134:134]++instr[125:125]++instr[124:124]++instr[123:123]++instr[122:122]++instr[121:121]++instr[112:112]++instr[111:111]++instr[110:110]++instr[109:109]++instr[108:108]++instr[99:99]++instr[98:98]++instr[97:97]++instr[96:96]++instr[95:95]++instr[86:86]++instr[85:85]++instr[84:84]++instr[83:83]++instr[82:82];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		
		temp_window=instr[137:137]++instr[136:136]++instr[135:135]++instr[134:134]++instr[133:133]++instr[124:124]++instr[123:123]++instr[122:122]++instr[121:121]++instr[120:120]++instr[111:111]++instr[110:110]++instr[109:109]++instr[108:108]++instr[107:107]++instr[98:98]++instr[97:97]++instr[96:96]++instr[95:95]++instr[94:94]++instr[85:85]++instr[84:84]++instr[83:83]++instr[82:82]++instr[81:81];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[136:136]++instr[135:135]++instr[134:134]++instr[133:133]++instr[132:132]++instr[123:123]++instr[122:122]++instr[121:121]++instr[120:120]++instr[119:119]++instr[110:110]++instr[109:109]++instr[108:108]++instr[107:107]++instr[106:106]++instr[97:97]++instr[96:96]++instr[95:95]++instr[94:94]++instr[93:93]++instr[84:84]++instr[83:83]++instr[82:82]++instr[81:81]++instr[80:80];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[135:135]++instr[134:134]++instr[133:133]++instr[132:132]++instr[131:131]++instr[122:122]++instr[121:121]++instr[120:120]++instr[119:119]++instr[118:118]++instr[109:109]++instr[108:108]++instr[107:107]++instr[106:106]++instr[105:105]++instr[96:96]++instr[95:95]++instr[94:94]++instr[93:93]++instr[92:92]++instr[83:83]++instr[82:82]++instr[81:81]++instr[80:80]++instr[79:79];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[134:134]++instr[133:133]++instr[132:132]++instr[131:131]++instr[130:130]++instr[121:121]++instr[120:120]++instr[119:119]++instr[118:118]++instr[117:117]++instr[108:108]++instr[107:107]++instr[106:106]++instr[105:105]++instr[104:104]++instr[95:95]++instr[94:94]++instr[93:93]++instr[92:92]++instr[91:91]++instr[82:82]++instr[81:81]++instr[80:80]++instr[79:79]++instr[78:78];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
	
		temp_window=instr[129:129]++instr[128:128]++instr[127:127]++instr[126:126]++instr[125:125]++instr[116:116]++instr[115:115]++instr[114:114]++instr[113:113]++instr[112:112]++instr[103:103]++instr[102:102]++instr[101:101]++instr[100:100]++instr[99:99]++instr[90:90]++instr[89:89]++instr[88:88]++instr[87:87]++instr[86:86]++instr[77:77]++instr[76:76]++instr[75:75]++instr[74:74]++instr[73:73];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[128:128]++instr[127:127]++instr[126:126]++instr[125:125]++instr[124:124]++instr[115:115]++instr[114:114]++instr[113:113]++instr[112:112]++instr[111:111]++instr[102:102]++instr[101:101]++instr[100:100]++instr[99:99]++instr[98:98]++instr[89:89]++instr[88:88]++instr[87:87]++instr[86:86]++instr[85:85]++instr[76:76]++instr[75:75]++instr[74:74]++instr[73:73]++instr[72:72];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[127:127]++instr[126:126]++instr[125:125]++instr[124:124]++instr[123:123]++instr[114:114]++instr[113:113]++instr[112:112]++instr[111:111]++instr[110:110]++instr[101:101]++instr[100:100]++instr[99:99]++instr[98:98]++instr[97:97]++instr[88:88]++instr[87:87]++instr[86:86]++instr[85:85]++instr[84:84]++instr[75:75]++instr[74:74]++instr[73:73]++instr[72:72]++instr[71:71];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[126:126]++instr[125:125]++instr[124:124]++instr[123:123]++instr[122:122]++instr[113:113]++instr[112:112]++instr[111:111]++instr[110:110]++instr[109:109]++instr[100:100]++instr[99:99]++instr[98:98]++instr[97:97]++instr[96:96]++instr[87:87]++instr[86:86]++instr[85:85]++instr[84:84]++instr[83:83]++instr[74:74]++instr[73:73]++instr[72:72]++instr[71:71]++instr[70:70];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[125:125]++instr[124:124]++instr[123:123]++instr[122:122]++instr[121:121]++instr[112:112]++instr[111:111]++instr[110:110]++instr[109:109]++instr[108:108]++instr[99:99]++instr[98:98]++instr[97:97]++instr[96:96]++instr[95:95]++instr[86:86]++instr[85:85]++instr[84:84]++instr[83:83]++instr[82:82]++instr[73:73]++instr[72:72]++instr[71:71]++instr[70:70]++instr[69:69];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[124:124]++instr[123:123]++instr[122:122]++instr[121:121]++instr[120:120]++instr[111:111]++instr[110:110]++instr[109:109]++instr[108:108]++instr[107:107]++instr[98:98]++instr[97:97]++instr[96:96]++instr[95:95]++instr[94:94]++instr[85:85]++instr[84:84]++instr[83:83]++instr[82:82]++instr[81:81]++instr[72:72]++instr[71:71]++instr[70:70]++instr[69:69]++instr[68:68];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[123:123]++instr[122:122]++instr[121:121]++instr[120:120]++instr[119:119]++instr[110:110]++instr[109:109]++instr[108:108]++instr[107:107]++instr[106:106]++instr[97:97]++instr[96:96]++instr[95:95]++instr[94:94]++instr[93:93]++instr[84:84]++instr[83:83]++instr[82:82]++instr[81:81]++instr[80:80]++instr[71:71]++instr[70:70]++instr[69:69]++instr[68:68]++instr[67:67];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[122:122]++instr[121:121]++instr[120:120]++instr[119:119]++instr[118:118]++instr[109:109]++instr[108:108]++instr[107:107]++instr[106:106]++instr[105:105]++instr[96:96]++instr[95:95]++instr[94:94]++instr[93:93]++instr[92:92]++instr[83:83]++instr[82:82]++instr[81:81]++instr[80:80]++instr[79:79]++instr[70:70]++instr[69:69]++instr[68:68]++instr[67:67]++instr[66:66];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[121:121]++instr[120:120]++instr[119:119]++instr[118:118]++instr[117:117]++instr[108:108]++instr[107:107]++instr[106:106]++instr[105:105]++instr[104:104]++instr[95:95]++instr[94:94]++instr[93:93]++instr[92:92]++instr[91:91]++instr[82:82]++instr[81:81]++instr[80:80]++instr[79:79]++instr[78:78]++instr[69:69]++instr[68:68]++instr[67:67]++instr[66:66]++instr[65:65];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		

		temp_window=instr[116:116]++instr[115:115]++instr[114:114]++instr[113:113]++instr[112:112]++instr[103:103]++instr[102:102]++instr[101:101]++instr[100:100]++instr[99:99]++instr[90:90]++instr[89:89]++instr[88:88]++instr[87:87]++instr[86:86]++instr[77:77]++instr[76:76]++instr[75:75]++instr[74:74]++instr[73:73]++instr[64:64]++instr[63:63]++instr[62:62]++instr[61:61]++instr[60:60];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[115:115]++instr[114:114]++instr[113:113]++instr[112:112]++instr[111:111]++instr[102:102]++instr[101:101]++instr[100:100]++instr[99:99]++instr[98:98]++instr[89:89]++instr[88:88]++instr[87:87]++instr[86:86]++instr[85:85]++instr[76:76]++instr[75:75]++instr[74:74]++instr[73:73]++instr[72:72]++instr[63:63]++instr[62:62]++instr[61:61]++instr[60:60]++instr[59:59];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[114:114]++instr[113:113]++instr[112:112]++instr[111:111]++instr[110:110]++instr[101:101]++instr[100:100]++instr[99:99]++instr[98:98]++instr[97:97]++instr[88:88]++instr[87:87]++instr[86:86]++instr[85:85]++instr[84:84]++instr[75:75]++instr[74:74]++instr[73:73]++instr[72:72]++instr[71:71]++instr[62:62]++instr[61:61]++instr[60:60]++instr[59:59]++instr[58:58];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		temp_window=instr[113:113]++instr[112:112]++instr[111:111]++instr[110:110]++instr[109:109]++instr[100:100]++instr[99:99]++instr[98:98]++instr[97:97]++instr[96:96]++instr[87:87]++instr[86:86]++instr[85:85]++instr[84:84]++instr[83:83]++instr[74:74]++instr[73:73]++instr[72:72]++instr[71:71]++instr[70:70]++instr[61:61]++instr[60:60]++instr[59:59]++instr[58:58]++instr[57:57];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[112:112]++instr[111:111]++instr[110:110]++instr[109:109]++instr[108:108]++instr[99:99]++instr[98:98]++instr[97:97]++instr[96:96]++instr[95:95]++instr[86:86]++instr[85:85]++instr[84:84]++instr[83:83]++instr[82:82]++instr[73:73]++instr[72:72]++instr[71:71]++instr[70:70]++instr[69:69]++instr[60:60]++instr[59:59]++instr[58:58]++instr[57:57]++instr[56:56];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[111:111]++instr[110:110]++instr[109:109]++instr[108:108]++instr[107:107]++instr[98:98]++instr[97:97]++instr[96:96]++instr[95:95]++instr[94:94]++instr[85:85]++instr[84:84]++instr[83:83]++instr[82:82]++instr[81:81]++instr[72:72]++instr[71:71]++instr[70:70]++instr[69:69]++instr[68:68]++instr[59:59]++instr[58:58]++instr[57:57]++instr[56:56]++instr[55:55];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[110:110]++instr[109:109]++instr[108:108]++instr[107:107]++instr[106:106]++instr[97:97]++instr[96:96]++instr[95:95]++instr[94:94]++instr[93:93]++instr[84:84]++instr[83:83]++instr[82:82]++instr[81:81]++instr[80:80]++instr[71:71]++instr[70:70]++instr[69:69]++instr[68:68]++instr[67:67]++instr[58:58]++instr[57:57]++instr[56:56]++instr[55:55]++instr[54:54];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[109:109]++instr[108:108]++instr[107:107]++instr[106:106]++instr[105:105]++instr[96:96]++instr[95:95]++instr[94:94]++instr[93:93]++instr[92:92]++instr[83:83]++instr[82:82]++instr[81:81]++instr[80:80]++instr[79:79]++instr[70:70]++instr[69:69]++instr[68:68]++instr[67:67]++instr[66:66]++instr[57:57]++instr[56:56]++instr[55:55]++instr[54:54]++instr[53:53];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[108:108]++instr[107:107]++instr[106:106]++instr[105:105]++instr[104:104]++instr[95:95]++instr[94:94]++instr[93:93]++instr[92:92]++instr[91:91]++instr[82:82]++instr[81:81]++instr[80:80]++instr[79:79]++instr[78:78]++instr[69:69]++instr[68:68]++instr[67:67]++instr[66:66]++instr[65:65]++instr[56:56]++instr[55:55]++instr[54:54]++instr[53:53]++instr[52:52];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[103:103]++instr[102:102]++instr[101:101]++instr[100:100]++instr[99:99]++instr[90:90]++instr[89:89]++instr[88:88]++instr[87:87]++instr[86:86]++instr[77:77]++instr[76:76]++instr[75:75]++instr[74:74]++instr[73:73]++instr[64:64]++instr[63:63]++instr[62:62]++instr[61:61]++instr[60:60]++instr[51:51]++instr[50:50]++instr[49:49]++instr[48:48]++instr[47:47];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[102:102]++instr[101:101]++instr[100:100]++instr[99:99]++instr[98:98]++instr[89:89]++instr[88:88]++instr[87:87]++instr[86:86]++instr[85:85]++instr[76:76]++instr[75:75]++instr[74:74]++instr[73:73]++instr[72:72]++instr[63:63]++instr[62:62]++instr[61:61]++instr[60:60]++instr[59:59]++instr[50:50]++instr[49:49]++instr[48:48]++instr[47:47]++instr[46:46];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		temp_window=instr[101:101]++instr[100:100]++instr[99:99]++instr[98:98]++instr[97:97]++instr[88:88]++instr[87:87]++instr[86:86]++instr[85:85]++instr[84:84]++instr[75:75]++instr[74:74]++instr[73:73]++instr[72:72]++instr[71:71]++instr[62:62]++instr[61:61]++instr[60:60]++instr[59:59]++instr[58:58]++instr[49:49]++instr[48:48]++instr[47:47]++instr[46:46]++instr[45:45];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[100:100]++instr[99:99]++instr[98:98]++instr[97:97]++instr[96:96]++instr[87:87]++instr[86:86]++instr[85:85]++instr[84:84]++instr[83:83]++instr[74:74]++instr[73:73]++instr[72:72]++instr[71:71]++instr[70:70]++instr[61:61]++instr[60:60]++instr[59:59]++instr[58:58]++instr[57:57]++instr[48:48]++instr[47:47]++instr[46:46]++instr[45:45]++instr[44:44];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		temp_window=instr[99:99]++instr[98:98]++instr[97:97]++instr[96:96]++instr[95:95]++instr[86:86]++instr[85:85]++instr[84:84]++instr[83:83]++instr[82:82]++instr[73:73]++instr[72:72]++instr[71:71]++instr[70:70]++instr[69:69]++instr[60:60]++instr[59:59]++instr[58:58]++instr[57:57]++instr[56:56]++instr[47:47]++instr[46:46]++instr[45:45]++instr[44:44]++instr[43:43];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[98:98]++instr[97:97]++instr[96:96]++instr[95:95]++instr[94:94]++instr[85:85]++instr[84:84]++instr[83:83]++instr[82:82]++instr[81:81]++instr[72:72]++instr[71:71]++instr[70:70]++instr[69:69]++instr[68:68]++instr[59:59]++instr[58:58]++instr[57:57]++instr[56:56]++instr[55:55]++instr[46:46]++instr[45:45]++instr[44:44]++instr[43:43]++instr[42:42];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[97:97]++instr[96:96]++instr[95:95]++instr[94:94]++instr[93:93]++instr[84:84]++instr[83:83]++instr[82:82]++instr[81:81]++instr[80:80]++instr[71:71]++instr[70:70]++instr[69:69]++instr[68:68]++instr[67:67]++instr[58:58]++instr[57:57]++instr[56:56]++instr[55:55]++instr[54:54]++instr[45:45]++instr[44:44]++instr[43:43]++instr[42:42]++instr[41:41];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		
		temp_window=instr[96:96]++instr[95:95]++instr[94:94]++instr[93:93]++instr[92:92]++instr[83:83]++instr[82:82]++instr[81:81]++instr[80:80]++instr[79:79]++instr[70:70]++instr[69:69]++instr[68:68]++instr[67:67]++instr[66:66]++instr[57:57]++instr[56:56]++instr[55:55]++instr[54:54]++instr[53:53]++instr[44:44]++instr[43:43]++instr[42:42]++instr[41:41]++instr[40:40];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[95:95]++instr[94:94]++instr[93:93]++instr[92:92]++instr[91:91]++instr[82:82]++instr[81:81]++instr[80:80]++instr[79:79]++instr[78:78]++instr[69:69]++instr[68:68]++instr[67:67]++instr[66:66]++instr[65:65]++instr[56:56]++instr[55:55]++instr[54:54]++instr[53:53]++instr[52:52]++instr[43:43]++instr[42:42]++instr[41:41]++instr[40:40]++instr[39:39];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[90:90]++instr[89:89]++instr[88:88]++instr[87:87]++instr[86:86]++instr[77:77]++instr[76:76]++instr[75:75]++instr[74:74]++instr[73:73]++instr[64:64]++instr[63:63]++instr[62:62]++instr[61:61]++instr[60:60]++instr[51:51]++instr[50:50]++instr[49:49]++instr[48:48]++instr[47:47]++instr[38:38]++instr[37:37]++instr[36:36]++instr[35:35]++instr[34:34];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[89:89]++instr[88:88]++instr[87:87]++instr[86:86]++instr[85:85]++instr[76:76]++instr[75:75]++instr[74:74]++instr[73:73]++instr[72:72]++instr[63:63]++instr[62:62]++instr[61:61]++instr[60:60]++instr[59:59]++instr[50:50]++instr[49:49]++instr[48:48]++instr[47:47]++instr[46:46]++instr[37:37]++instr[36:36]++instr[35:35]++instr[34:34]++instr[33:33];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[88:88]++instr[87:87]++instr[86:86]++instr[85:85]++instr[84:84]++instr[75:75]++instr[74:74]++instr[73:73]++instr[72:72]++instr[71:71]++instr[62:62]++instr[61:61]++instr[60:60]++instr[59:59]++instr[58:58]++instr[49:49]++instr[48:48]++instr[47:47]++instr[46:46]++instr[45:45]++instr[36:36]++instr[35:35]++instr[34:34]++instr[33:33]++instr[32:32];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[87:87]++instr[86:86]++instr[85:85]++instr[84:84]++instr[83:83]++instr[74:74]++instr[73:73]++instr[72:72]++instr[71:71]++instr[70:70]++instr[61:61]++instr[60:60]++instr[59:59]++instr[58:58]++instr[57:57]++instr[48:48]++instr[47:47]++instr[46:46]++instr[45:45]++instr[44:44]++instr[35:35]++instr[34:34]++instr[33:33]++instr[32:32]++instr[31:31];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[86:86]++instr[85:85]++instr[84:84]++instr[83:83]++instr[82:82]++instr[73:73]++instr[72:72]++instr[71:71]++instr[70:70]++instr[69:69]++instr[60:60]++instr[59:59]++instr[58:58]++instr[57:57]++instr[56:56]++instr[47:47]++instr[46:46]++instr[45:45]++instr[44:44]++instr[43:43]++instr[34:34]++instr[33:33]++instr[32:32]++instr[31:31]++instr[30:30];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[85:85]++instr[84:84]++instr[83:83]++instr[82:82]++instr[81:81]++instr[72:72]++instr[71:71]++instr[70:70]++instr[69:69]++instr[68:68]++instr[59:59]++instr[58:58]++instr[57:57]++instr[56:56]++instr[55:55]++instr[46:46]++instr[45:45]++instr[44:44]++instr[43:43]++instr[42:42]++instr[33:33]++instr[32:32]++instr[31:31]++instr[30:30]++instr[29:29];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[84:84]++instr[83:83]++instr[82:82]++instr[81:81]++instr[80:80]++instr[71:71]++instr[70:70]++instr[69:69]++instr[68:68]++instr[67:67]++instr[58:58]++instr[57:57]++instr[56:56]++instr[55:55]++instr[54:54]++instr[45:45]++instr[44:44]++instr[43:43]++instr[42:42]++instr[41:41]++instr[32:32]++instr[31:31]++instr[30:30]++instr[29:29]++instr[28:28];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[83:83]++instr[82:82]++instr[81:81]++instr[80:80]++instr[79:79]++instr[70:70]++instr[69:69]++instr[68:68]++instr[67:67]++instr[66:66]++instr[57:57]++instr[56:56]++instr[55:55]++instr[54:54]++instr[53:53]++instr[44:44]++instr[43:43]++instr[42:42]++instr[41:41]++instr[40:40]++instr[31:31]++instr[30:30]++instr[29:29]++instr[28:28]++instr[27:27];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[82:82]++instr[81:81]++instr[80:80]++instr[79:79]++instr[78:78]++instr[69:69]++instr[68:68]++instr[67:67]++instr[66:66]++instr[65:65]++instr[56:56]++instr[55:55]++instr[54:54]++instr[53:53]++instr[52:52]++instr[43:43]++instr[42:42]++instr[41:41]++instr[40:40]++instr[39:39]++instr[30:30]++instr[29:29]++instr[28:28]++instr[27:27]++instr[26:26];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		
		temp_window=instr[77:77]++instr[76:76]++instr[75:75]++instr[74:74]++instr[73:73]++instr[64:64]++instr[63:63]++instr[62:62]++instr[61:61]++instr[60:60]++instr[51:51]++instr[50:50]++instr[49:49]++instr[48:48]++instr[47:47]++instr[38:38]++instr[37:37]++instr[36:36]++instr[35:35]++instr[34:34]++instr[25:25]++instr[24:24]++instr[23:23]++instr[22:22]++instr[21:21];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[76:76]++instr[75:75]++instr[74:74]++instr[73:73]++instr[72:72]++instr[63:63]++instr[62:62]++instr[61:61]++instr[60:60]++instr[59:59]++instr[50:50]++instr[49:49]++instr[48:48]++instr[47:47]++instr[46:46]++instr[37:37]++instr[36:36]++instr[35:35]++instr[34:34]++instr[33:33]++instr[24:24]++instr[23:23]++instr[22:22]++instr[21:21]++instr[20:20];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[75:75]++instr[74:74]++instr[73:73]++instr[72:72]++instr[71:71]++instr[62:62]++instr[61:61]++instr[60:60]++instr[59:59]++instr[58:58]++instr[49:49]++instr[48:48]++instr[47:47]++instr[46:46]++instr[45:45]++instr[36:36]++instr[35:35]++instr[34:34]++instr[33:33]++instr[32:32]++instr[23:23]++instr[22:22]++instr[21:21]++instr[20:20]++instr[19:19];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[74:74]++instr[73:73]++instr[72:72]++instr[71:71]++instr[70:70]++instr[61:61]++instr[60:60]++instr[59:59]++instr[58:58]++instr[57:57]++instr[48:48]++instr[47:47]++instr[46:46]++instr[45:45]++instr[44:44]++instr[35:35]++instr[34:34]++instr[33:33]++instr[32:32]++instr[31:31]++instr[22:22]++instr[21:21]++instr[20:20]++instr[19:19]++instr[18:18];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[73:73]++instr[72:72]++instr[71:71]++instr[70:70]++instr[69:69]++instr[60:60]++instr[59:59]++instr[58:58]++instr[57:57]++instr[56:56]++instr[47:47]++instr[46:46]++instr[45:45]++instr[44:44]++instr[43:43]++instr[34:34]++instr[33:33]++instr[32:32]++instr[31:31]++instr[30:30]++instr[21:21]++instr[20:20]++instr[19:19]++instr[18:18]++instr[17:17];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[72:72]++instr[71:71]++instr[70:70]++instr[69:69]++instr[68:68]++instr[59:59]++instr[58:58]++instr[57:57]++instr[56:56]++instr[55:55]++instr[46:46]++instr[45:45]++instr[44:44]++instr[43:43]++instr[42:42]++instr[33:33]++instr[32:32]++instr[31:31]++instr[30:30]++instr[29:29]++instr[20:20]++instr[19:19]++instr[18:18]++instr[17:17]++instr[16:16];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[71:71]++instr[70:70]++instr[69:69]++instr[68:68]++instr[67:67]++instr[58:58]++instr[57:57]++instr[56:56]++instr[55:55]++instr[54:54]++instr[45:45]++instr[44:44]++instr[43:43]++instr[42:42]++instr[41:41]++instr[32:32]++instr[31:31]++instr[30:30]++instr[29:29]++instr[28:28]++instr[19:19]++instr[18:18]++instr[17:17]++instr[16:16]++instr[15:15];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[70:70]++instr[69:69]++instr[68:68]++instr[67:67]++instr[66:66]++instr[57:57]++instr[56:56]++instr[55:55]++instr[54:54]++instr[53:53]++instr[44:44]++instr[43:43]++instr[42:42]++instr[41:41]++instr[40:40]++instr[31:31]++instr[30:30]++instr[29:29]++instr[28:28]++instr[27:27]++instr[18:18]++instr[17:17]++instr[16:16]++instr[15:15]++instr[14:14];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[69:69]++instr[68:68]++instr[67:67]++instr[66:66]++instr[65:65]++instr[56:56]++instr[55:55]++instr[54:54]++instr[53:53]++instr[52:52]++instr[43:43]++instr[42:42]++instr[41:41]++instr[40:40]++instr[39:39]++instr[30:30]++instr[29:29]++instr[28:28]++instr[27:27]++instr[26:26]++instr[17:17]++instr[16:16]++instr[15:15]++instr[14:14]++instr[13:13];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[64:64]++instr[63:63]++instr[62:62]++instr[61:61]++instr[60:60]++instr[51:51]++instr[50:50]++instr[49:49]++instr[48:48]++instr[47:47]++instr[38:38]++instr[37:37]++instr[36:36]++instr[35:35]++instr[34:34]++instr[25:25]++instr[24:24]++instr[23:23]++instr[22:22]++instr[21:21]++instr[12:12]++instr[11:11]++instr[10:10]++instr[9:9]++instr[8:8];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[63:63]++instr[62:62]++instr[61:61]++instr[60:60]++instr[59:59]++instr[50:50]++instr[49:49]++instr[48:48]++instr[47:47]++instr[46:46]++instr[37:37]++instr[36:36]++instr[35:35]++instr[34:34]++instr[33:33]++instr[24:24]++instr[23:23]++instr[22:22]++instr[21:21]++instr[20:20]++instr[11:11]++instr[10:10]++instr[9:9]++instr[8:8]++instr[7:7];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[62:62]++instr[61:61]++instr[60:60]++instr[59:59]++instr[58:58]++instr[49:49]++instr[48:48]++instr[47:47]++instr[46:46]++instr[45:45]++instr[36:36]++instr[35:35]++instr[34:34]++instr[33:33]++instr[32:32]++instr[23:23]++instr[22:22]++instr[21:21]++instr[20:20]++instr[19:19]++instr[10:10]++instr[9:9]++instr[8:8]++instr[7:7]++instr[6:6];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[61:61]++instr[60:60]++instr[59:59]++instr[58:58]++instr[57:57]++instr[48:48]++instr[47:47]++instr[46:46]++instr[45:45]++instr[44:44]++instr[35:35]++instr[34:34]++instr[33:33]++instr[32:32]++instr[31:31]++instr[22:22]++instr[21:21]++instr[20:20]++instr[19:19]++instr[18:18]++instr[9:9]++instr[8:8]++instr[7:7]++instr[6:6]++instr[5:5];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[60:60]++instr[59:59]++instr[58:58]++instr[57:57]++instr[56:56]++instr[47:47]++instr[46:46]++instr[45:45]++instr[44:44]++instr[43:43]++instr[34:34]++instr[33:33]++instr[32:32]++instr[31:31]++instr[30:30]++instr[21:21]++instr[20:20]++instr[19:19]++instr[18:18]++instr[17:17]++instr[8:8]++instr[7:7]++instr[6:6]++instr[5:5]++instr[4:4];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[59:59]++instr[58:58]++instr[57:57]++instr[56:56]++instr[55:55]++instr[46:46]++instr[45:45]++instr[44:44]++instr[43:43]++instr[42:42]++instr[33:33]++instr[32:32]++instr[31:31]++instr[30:30]++instr[29:29]++instr[20:20]++instr[19:19]++instr[18:18]++instr[17:17]++instr[16:16]++instr[7:7]++instr[6:6]++instr[5:5]++instr[4:4]++instr[3:3];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[58:58]++instr[57:57]++instr[56:56]++instr[55:55]++instr[54:54]++instr[45:45]++instr[44:44]++instr[43:43]++instr[42:42]++instr[41:41]++instr[32:32]++instr[31:31]++instr[30:30]++instr[29:29]++instr[28:28]++instr[19:19]++instr[18:18]++instr[17:17]++instr[16:16]++instr[15:15]++instr[6:6]++instr[5:5]++instr[4:4]++instr[3:3]++instr[2:2];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		temp_window=instr[57:57]++instr[56:56]++instr[55:55]++instr[54:54]++instr[53:53]++instr[44:44]++instr[43:43]++instr[42:42]++instr[41:41]++instr[40:40]++instr[31:31]++instr[30:30]++instr[29:29]++instr[28:28]++instr[27:27]++instr[18:18]++instr[17:17]++instr[16:16]++instr[15:15]++instr[14:14]++instr[5:5]++instr[4:4]++instr[3:3]++instr[2:2]++instr[1:1];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_window=instr[56:56]++instr[55:55]++instr[54:54]++instr[53:53]++instr[52:52]++instr[43:43]++instr[42:42]++instr[41:41]++instr[40:40]++instr[39:39]++instr[30:30]++instr[29:29]++instr[28:28]++instr[27:27]++instr[26:26]++instr[17:17]++instr[16:16]++instr[15:15]++instr[14:14]++instr[13:13]++instr[4:4]++instr[3:3]++instr[2:2]++instr[1:1]++instr[0:0];
		CXNOR(temp_weight1,temp_window);
        CBitCount(CXNOROutput);
		NResponse1=NResponse1<<1;
        NResponse1=NResponse1+(bit<81>)CResponse;
        CXNOR(temp_weight2,temp_window);
        CBitCount(CXNOROutput);
		NResponse2=NResponse2<<1;
        NResponse2=NResponse2+(bit<81>)CResponse;
        CXNOR(temp_weight3,temp_window);
        CBitCount(CXNOROutput);
		NResponse3=NResponse3<<1;
        NResponse3=NResponse3+(bit<81>)CResponse;
        CXNOR(temp_weight4,temp_window);
        CBitCount(CXNOROutput);
		NResponse4=NResponse4<<1;
        NResponse4=NResponse4+(bit<81>)CResponse;
        CXNOR(temp_weight5,temp_window);
        CBitCount(CXNOROutput);
		NResponse5=NResponse5<<1;
        NResponse5=NResponse5+(bit<81>)CResponse;
        CXNOR(temp_weight6,temp_window);
        CBitCount(CXNOROutput);
		NResponse6=NResponse6<<1;
        NResponse6=NResponse6+(bit<81>)CResponse;
        CXNOR(temp_weight7,temp_window);
        CBitCount(CXNOROutput);
		NResponse7=NResponse7<<1;
        NResponse7=NResponse7+(bit<81>)CResponse;
        CXNOR(temp_weight8,temp_window);
        CBitCount(CXNOROutput);
		NResponse8=NResponse8<<1;
        NResponse8=NResponse8+(bit<81>)CResponse;
		
		temp_holder=NResponse8;

		
		if (flag==0) {
			CNeuronRes1.write(0,temp_holder);
		}
		else if (flag==1) {
			CNeuronRes2.write(0,temp_holder);
		}
		else if (flag==2) {
			CNeuronRes3.write(0,temp_holder);
		}
		else if (flag==3) {
			CNeuronRes4.write(0,temp_holder);
		}
		else if (flag==4) {
			CNeuronRes5.write(0,temp_holder);
		}
		else if (flag==5) {
			CNeuronRes6.write(0,temp_holder);
		}
		else if (flag==6) {
			CNeuronRes7.write(0,temp_holder);
		}
		else if (flag==7) {
			CNeuronRes8.write(0,temp_holder);
		}
		else if (flag==8) {
			CNeuronRes9.write(0,temp_holder);
		}
		else if (flag==9) {
			CNeuronRes10.write(0,temp_holder);
		}
		else if (flag==10) {
			CNeuronRes11.write(0,temp_holder);
		}
		else if (flag==11) {
			CNeuronRes12.write(0,temp_holder);
		}
		else if (flag==12) {
			CNeuronRes13.write(0,temp_holder);
		}
		else if (flag==13) {
			CNeuronRes14.write(0,temp_holder);
		}
		else if (flag==14) {
			CNeuronRes15.write(0,temp_holder);
		}
		else if (flag==15) {
			CNeuronRes16.write(0,temp_holder);
		}
		else if (flag==16) {
			CNeuronRes17.write(0,temp_holder);
		}
		else if (flag==17) {
			CNeuronRes18.write(0,temp_holder);
		}
		else if (flag==18) {
			CNeuronRes19.write(0,temp_holder);
		}
		else if (flag==19) {
			CNeuronRes20.write(0,temp_holder);
		}
		else if (flag==20) {
			CNeuronRes21.write(0,temp_holder);
		}
		else if (flag==21) {
			CNeuronRes22.write(0,temp_holder);
		}
		else if (flag==22) {
			CNeuronRes23.write(0,temp_holder);
		}
		else if (flag==23) {
			CNeuronRes24.write(0,temp_holder);
		}
		else if (flag==24) {
			CNeuronRes25.write(0,temp_holder);
		}
		else if (flag==25) {
			CNeuronRes26.write(0,temp_holder);
		}
		else if (flag==26) {
			CNeuronRes27.write(0,temp_holder);
		}
		else if (flag==27) {
			CNeuronRes28.write(0,temp_holder);
		}
		else if (flag==28) {
			CNeuronRes29.write(0,temp_holder);
		}
		else if (flag==29) {
			CNeuronRes30.write(0,temp_holder);
		}
		else if (flag==30) {
			CNeuronRes31.write(0,temp_holder);
		}
		else if (flag==31) {
			CNeuronRes32.write(0,temp_holder);
		}
		else if (flag==32) {
			CNeuronRes33.write(0,temp_holder);
		}
		else if (flag==33) {
			CNeuronRes34.write(0,temp_holder);
		}
		else if (flag==34) {
			CNeuronRes35.write(0,temp_holder);
		}
		else if (flag==35) {
			CNeuronRes36.write(0,temp_holder);
		}
		else if (flag==36) {
			CNeuronRes37.write(0,temp_holder);
		}
		else if (flag==37) {
			CNeuronRes38.write(0,temp_holder);
		}
		else if (flag==38) {
			CNeuronRes39.write(0,temp_holder);
		}
		else if (flag==39) {
			CNeuronRes40.write(0,temp_holder);
		}
		else if (flag==40) {
			CNeuronRes41.write(0,temp_holder);
		}
		else if (flag==41) {
			CNeuronRes42.write(0,temp_holder);
		}
		else if (flag==42) {
			CNeuronRes43.write(0,temp_holder);
		}
		else if (flag==43) {
			CNeuronRes44.write(0,temp_holder);
		}
		else if (flag==44) {
			CNeuronRes45.write(0,temp_holder);
		}
		else if (flag==45) {
			CNeuronRes46.write(0,temp_holder);
		}
		else if (flag==46) {
			CNeuronRes47.write(0,temp_holder);
		}
		else if (flag==47) {
			CNeuronRes48.write(0,temp_holder);
		}
		else if (flag==48) {
			CNeuronRes49.write(0,temp_holder);
		}
		else if (flag==49) {
			CNeuronRes50.write(0,temp_holder);
		}
		else if (flag==50) {
			CNeuronRes51.write(0,temp_holder);
		}
		else if (flag==51) {
			CNeuronRes52.write(0,temp_holder);
		}
		else if (flag==52) {
			CNeuronRes53.write(0,temp_holder);
		}
		else if (flag==53) {
			CNeuronRes54.write(0,temp_holder);
		}
		else if (flag==54) {
			CNeuronRes55.write(0,temp_holder);
		}
		else if (flag==55) {
			CNeuronRes56.write(0,temp_holder);
		}
		else if (flag==56) {
			CNeuronRes57.write(0,temp_holder);
		}
		else if (flag==57) {
			CNeuronRes58.write(0,temp_holder);
		}
		else if (flag==58) {
			CNeuronRes59.write(0,temp_holder);
		}
		else if (flag==59) {
			CNeuronRes60.write(0,temp_holder);
		}
		else if (flag==60) {
			CNeuronRes61.write(0,temp_holder);
		}
		else if (flag==61) {
			CNeuronRes62.write(0,temp_holder);
		}
		else if (flag==62) {
			CNeuronRes63.write(0,temp_holder);
		}
		else if (flag==63) {
			CNeuronRes64.write(0,temp_holder);
		}

		
		if (packetno==64) {
			CNeuronRes1.read(temp_res,flag);				//if last packet, finalize the response values
			hdr.fcr.ConvRes1=temp_res;
			CNeuronRes2.read(temp_res,flag);
			hdr.fcr.ConvRes2=temp_res;
			CNeuronRes3.read(temp_res,flag);
			hdr.fcr.ConvRes3=temp_res;
			CNeuronRes4.read(temp_res,flag);
			hdr.fcr.ConvRes4=temp_res;
			CNeuronRes5.read(temp_res,flag);
			hdr.fcr.ConvRes5=temp_res;
			CNeuronRes6.read(temp_res,flag);
			hdr.fcr.ConvRes6=temp_res;
			CNeuronRes7.read(temp_res,flag);
			hdr.fcr.ConvRes7=temp_res;
			CNeuronRes8.read(temp_res,flag);
			hdr.fcr.ConvRes8=temp_res;
			CNeuronRes9.read(temp_res,flag);
			hdr.fcr.ConvRes9=temp_res;
			CNeuronRes10.read(temp_res,flag);
			hdr.fcr.ConvRes10=temp_res;
			CNeuronRes11.read(temp_res,flag);
			hdr.fcr.ConvRes11=temp_res;
			CNeuronRes12.read(temp_res,flag);
			hdr.fcr.ConvRes12=temp_res;
			CNeuronRes13.read(temp_res,flag);
			hdr.fcr.ConvRes13=temp_res;
			CNeuronRes14.read(temp_res,flag);
			hdr.fcr.ConvRes14=temp_res;
			CNeuronRes15.read(temp_res,flag);
			hdr.fcr.ConvRes15=temp_res;
			CNeuronRes16.read(temp_res,flag);
			hdr.fcr.ConvRes16=temp_res;
			CNeuronRes17.read(temp_res,flag);
			hdr.fcr.ConvRes17=temp_res;
			CNeuronRes18.read(temp_res,flag);
			hdr.fcr.ConvRes18=temp_res;
			CNeuronRes19.read(temp_res,flag);
			hdr.fcr.ConvRes19=temp_res;
			CNeuronRes20.read(temp_res,flag);
			hdr.fcr.ConvRes20=temp_res;
			CNeuronRes21.read(temp_res,flag);
			hdr.fcr.ConvRes21=temp_res;
			CNeuronRes22.read(temp_res,flag);
			hdr.fcr.ConvRes22=temp_res;
			CNeuronRes23.read(temp_res,flag);
			hdr.fcr.ConvRes23=temp_res;
			CNeuronRes24.read(temp_res,flag);
			hdr.fcr.ConvRes24=temp_res;
			CNeuronRes25.read(temp_res,flag);
			hdr.fcr.ConvRes25=temp_res;
			CNeuronRes26.read(temp_res,flag);
			hdr.fcr.ConvRes26=temp_res;
			CNeuronRes27.read(temp_res,flag);
			hdr.fcr.ConvRes27=temp_res;
			CNeuronRes28.read(temp_res,flag);
			hdr.fcr.ConvRes28=temp_res;
			CNeuronRes29.read(temp_res,flag);
			hdr.fcr.ConvRes29=temp_res;
			CNeuronRes30.read(temp_res,flag);
			hdr.fcr.ConvRes30=temp_res;
			CNeuronRes31.read(temp_res,flag);
			hdr.fcr.ConvRes31=temp_res;
			CNeuronRes32.read(temp_res,flag);
			hdr.fcr.ConvRes32=temp_res;
			CNeuronRes33.read(temp_res,flag);
			hdr.fcr.ConvRes33=temp_res;
			CNeuronRes34.read(temp_res,flag);
			hdr.fcr.ConvRes34=temp_res;
			CNeuronRes35.read(temp_res,flag);
			hdr.fcr.ConvRes35=temp_res;
			CNeuronRes36.read(temp_res,flag);
			hdr.fcr.ConvRes36=temp_res;
			CNeuronRes37.read(temp_res,flag);
			hdr.fcr.ConvRes37=temp_res;
			CNeuronRes38.read(temp_res,flag);
			hdr.fcr.ConvRes38=temp_res;
			CNeuronRes39.read(temp_res,flag);
			hdr.fcr.ConvRes39=temp_res;
			CNeuronRes40.read(temp_res,flag);
			hdr.fcr.ConvRes40=temp_res;
			CNeuronRes41.read(temp_res,flag);
			hdr.fcr.ConvRes41=temp_res;
			CNeuronRes42.read(temp_res,flag);
			hdr.fcr.ConvRes42=temp_res;
			CNeuronRes43.read(temp_res,flag);
			hdr.fcr.ConvRes43=temp_res;
			CNeuronRes44.read(temp_res,flag);
			hdr.fcr.ConvRes44=temp_res;
			CNeuronRes45.read(temp_res,flag);
			hdr.fcr.ConvRes45=temp_res;
			CNeuronRes46.read(temp_res,flag);
			hdr.fcr.ConvRes46=temp_res;
			CNeuronRes47.read(temp_res,flag);
			hdr.fcr.ConvRes47=temp_res;
			CNeuronRes48.read(temp_res,flag);
			hdr.fcr.ConvRes48=temp_res;
			CNeuronRes49.read(temp_res,flag);
			hdr.fcr.ConvRes49=temp_res;
			CNeuronRes50.read(temp_res,flag);
			hdr.fcr.ConvRes50=temp_res;
			CNeuronRes51.read(temp_res,flag);
			hdr.fcr.ConvRes51=temp_res;
			CNeuronRes52.read(temp_res,flag);
			hdr.fcr.ConvRes52=temp_res;
			CNeuronRes53.read(temp_res,flag);
			hdr.fcr.ConvRes53=temp_res;
			CNeuronRes54.read(temp_res,flag);
			hdr.fcr.ConvRes54=temp_res;
			CNeuronRes55.read(temp_res,flag);
			hdr.fcr.ConvRes55=temp_res;
			CNeuronRes56.read(temp_res,flag);
			hdr.fcr.ConvRes56=temp_res;
			CNeuronRes57.read(temp_res,flag);
			hdr.fcr.ConvRes57=temp_res;
			CNeuronRes58.read(temp_res,flag);
			hdr.fcr.ConvRes58=temp_res;
			CNeuronRes59.read(temp_res,flag);
			hdr.fcr.ConvRes59=temp_res;
			CNeuronRes60.read(temp_res,flag);
			hdr.fcr.ConvRes60=temp_res;
			CNeuronRes61.read(temp_res,flag);
			hdr.fcr.ConvRes61=temp_res;
			CNeuronRes62.read(temp_res,flag);
			hdr.fcr.ConvRes62=temp_res;
			CNeuronRes63.read(temp_res,flag);
			hdr.fcr.ConvRes63=temp_res;
			CNeuronRes64.read(temp_res,flag);
			hdr.fcr.ConvRes64=temp_res;

			
			standard_metadata.egress_spec=4;
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
	packet.emit(hdr.udp);
	packet.emit(hdr.counts);
	packet.emit(hdr.fcr);
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

