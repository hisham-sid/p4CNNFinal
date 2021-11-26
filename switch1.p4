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
    bit<676> CNeu1;

	bit<11> empty;
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

    bit<32> gray_pixel1=32w0;
    bit<32> gray_pixel2=32w0;
    bit<32> gray_pixel3=32w0;
    bit<32> gray_pixel4=32w0;
    bit<32> gray_pixel5=32w0;			//converted grayscale values are stored here
    bit<32> gray_pixel6=32w0;
    bit<32> gray_pixel7=32w0;
    bit<32> gray_pixel8=32w0;
    bit<32> gray_pixel9=32w0;

    bit<8> gray_bit_pixel1=0;
    bit<8> gray_bit_pixel2=0;
    bit<8> gray_bit_pixel3=0;
    bit<8> gray_bit_pixel4=0;
    bit<8> gray_bit_pixel5=0;			//grayscale values converted to binary
    bit<8> gray_bit_pixel6=0;
    bit<8> gray_bit_pixel7=0;
    bit<8> gray_bit_pixel8=0;
    bit<8> gray_bit_pixel9=0;
	
    register<bit<8>>(9) CNeuron1;
    register<bit<8>>(9) CNeuron2;
    register<bit<8>>(9) CNeuron3;
    register<bit<8>>(9) CNeuron4;
    register<bit<8>>(9) CNeuron5;
    register<bit<8>>(9) CNeuron6;
    register<bit<8>>(9) CNeuron7;			//binary weights for the convolutional filters
    register<bit<8>>(9) CNeuron8;			


    register<bit<676>>(1) CNeuronRes1;
    register<bit<676>>(1) CNeuronRes2;
    register<bit<676>>(1) CNeuronRes3;
    register<bit<676>>(1) CNeuronRes4;
    register<bit<676>>(1) CNeuronRes5;
    register<bit<676>>(1) CNeuronRes6;        	//storing the responses of the convolutional layer
    register<bit<676>>(1) CNeuronRes7;
    register<bit<676>>(1) CNeuronRes8;

  
    mul() MulRed1;
    mul() MulGreen1;
    mul() MulBlue1;

    mul() MulRed2;
    mul() MulGreen2;
    mul() MulBlue2;

    mul() MulRed3;
    mul() MulGreen3;
    mul() MulBlue3;

    mul() MulRed4;
    mul() MulGreen4;
    mul() MulBlue4;

    mul() MulRed5;
    mul() MulGreen5;
    mul() MulBlue5;

    mul() MulRed6;
    mul() MulGreen6;
    mul() MulBlue6;

    mul() MulRed7;
    mul() MulGreen7;
    mul() MulBlue7;

    mul() MulRed8;
    mul() MulGreen8;
    mul() MulBlue8;

    mul() MulRed9;
    mul() MulGreen9;
    mul() MulBlue9;



    bit<128> m1 = 0x55555555555555555555555555555555;
    bit<128> m2 = 0x33333333333333333333333333333333;
    bit<128> m4 = 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f;
    bit<128> m8 = 0x00ff00ff00ff00ff00ff00ff00ff00ff;
    bit<128> m16= 0x0000ffff0000ffff0000ffff0000ffff;
    bit<128> m32= 0x00000000ffffffff00000000ffffffff;
    bit<128> m64= 0x0000000000000000ffffffffffffffff;


    bit<8> CXNOROutput=0;					 //output of XNOR for the Convolutional layer					
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

	//Convolutional layer XNOR, involving 8-bit operands
    action CXNOR(bit<8> weight, bit<8> pixel){
        CXNOROutput = weight^pixel;
        CXNOROutput = ~CXNOROutput;
    }
	//Convolutional layer popcount
    action CBitCount(bit<8> bitInput){
	bit<128> x= (bit<128>)bitInput;
	x = (x & m1 ) + ((x >>  1) & m1 ); 
	x = (x & m2 ) + ((x >>  2) & m2 );
	x = (x & m4 ) + ((x >>  4) & m4 );
	if (x>4) CResponse = 1;
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

        if (hdr.fcr.flag_value==1) {

		/* *********************************************** */
		/*                            CONVOLUTIONAL LAYER                        */
		/* ********************************************** */

            sequence_no=hdr.counts.sequence;
	        bit<32> red_M=32w6; //approx 0.299
	        bit<32> green_M=32w9; //approx 0.587
                bit<32> blue_M=32w2; //approx 0.114
	        bit<32> coeff_result=32w0;

	       //formula is gray=0.299*red + 0.587*green +0.114*blue, this is done for each pixel form the chunk
	       bit<32> red_C1=(bit<32>)hdr.colors.red1 << 4;
	       bit<32> green_C1=(bit<32>)hdr.colors.green1 << 4;
	       bit<32> blue_C1=(bit<32>)hdr.colors.blue1 << 4;
	       bit<32> red_C2=(bit<32>)hdr.colors.red2 << 4;
	       bit<32> green_C2=(bit<32>)hdr.colors.green2 << 4;
	       bit<32> blue_C2=(bit<32>)hdr.colors.blue2 << 4;
	       bit<32> red_C3=(bit<32>)hdr.colors.red3 << 4;
	       bit<32> green_C3=(bit<32>)hdr.colors.green3 << 4;
	       bit<32> blue_C3=(bit<32>)hdr.colors.blue3 << 4;
	       bit<32> red_C4=(bit<32>)hdr.colors.red4 << 4;
	       bit<32> green_C4=(bit<32>)hdr.colors.green4 << 4;
	       bit<32> blue_C4=(bit<32>)hdr.colors.blue4 << 4;
	       bit<32> red_C5=(bit<32>)hdr.colors.red5 << 4;
	       bit<32> green_C5=(bit<32>)hdr.colors.green5 << 4;
	       bit<32> blue_C5=(bit<32>)hdr.colors.blue5 << 4;
	       bit<32> red_C6=(bit<32>)hdr.colors.red6 << 4;
	       bit<32> green_C6=(bit<32>)hdr.colors.green6 << 4;
	       bit<32> blue_C6=(bit<32>)hdr.colors.blue6 << 4;
	       bit<32> red_C7=(bit<32>)hdr.colors.red7 << 4;
	       bit<32> green_C7=(bit<32>)hdr.colors.green7 << 4;
	       bit<32> blue_C7=(bit<32>)hdr.colors.blue7 << 4;
	       bit<32> red_C8=(bit<32>)hdr.colors.red8 << 4;
	       bit<32> green_C8=(bit<32>)hdr.colors.green8 << 4;
	       bit<32> blue_C8=(bit<32>)hdr.colors.blue8 << 4;
     	   bit<32> red_C9=(bit<32>)hdr.colors.red9 << 4;
	       bit<32> green_C9=(bit<32>)hdr.colors.green9 << 4;
	       bit<32> blue_C9=(bit<32>)hdr.colors.blue9 << 4;
            MulRed1.apply(red_M,red_C1,coeff_result);;
	        gray_pixel1=gray_pixel1+coeff_result;
	        MulGreen1.apply(green_M,green_C1,coeff_result);;						//using color information to convert to grayscale value for pixel 1
	        gray_pixel1=gray_pixel1+coeff_result;
	        MulBlue1.apply(blue_M,blue_C1,coeff_result);;
	        gray_pixel1=gray_pixel1+coeff_result;

	        MulRed2.apply(red_M,red_C2,coeff_result);;
	        gray_pixel2=gray_pixel2+coeff_result;
	        MulGreen2.apply(green_M,green_C2,coeff_result);;						//using color information to convert to grayscale value for pixel 2
	        gray_pixel2=gray_pixel2+coeff_result;
	        MulBlue2.apply(blue_M,blue_C2,coeff_result);;
	        gray_pixel2=gray_pixel2+coeff_result;

	        MulRed3.apply(red_M,red_C3,coeff_result);;
	        gray_pixel3=gray_pixel3+coeff_result;
	        MulGreen3.apply(green_M,green_C3,coeff_result);;						//using color information to convert to grayscale value for pixel 3
	        gray_pixel3=gray_pixel3+coeff_result;
	        MulBlue3.apply(blue_M,blue_C3,coeff_result);;
	        gray_pixel3=gray_pixel3+coeff_result;

	        MulRed4.apply(red_M,red_C4,coeff_result);;
	        gray_pixel4=gray_pixel4+coeff_result;
	        MulGreen4.apply(green_M,green_C4,coeff_result);;						//using color information to convert to grayscale value for pixel 4
	        gray_pixel4=gray_pixel4+coeff_result;
	        MulBlue4.apply(blue_M,blue_C4,coeff_result);;
	        gray_pixel4=gray_pixel4+coeff_result;

	        MulRed5.apply(red_M,red_C5,coeff_result);;
	        gray_pixel5=gray_pixel5+coeff_result;
	        MulGreen5.apply(green_M,green_C5,coeff_result);;						//using color information to convert to grayscale value for pixel 4
	        gray_pixel5=gray_pixel5+coeff_result;
	        MulBlue5.apply(blue_M,blue_C5,coeff_result);;
	        gray_pixel5=gray_pixel5+coeff_result;

	        MulRed6.apply(red_M,red_C6,coeff_result);;
	        gray_pixel6=gray_pixel6+coeff_result;
	        MulGreen6.apply(green_M,green_C6,coeff_result);;						//using color information to convert to grayscale value for pixel 4
	        gray_pixel6=gray_pixel6+coeff_result;
	        MulBlue6.apply(blue_M,blue_C6,coeff_result);;
	        gray_pixel6=gray_pixel6+coeff_result;

	        MulRed7.apply(red_M,red_C7,coeff_result);;
	        gray_pixel7=gray_pixel7+coeff_result;
	        MulGreen7.apply(green_M,green_C7,coeff_result);;						//using color information to convert to grayscale value for pixel 4
	        gray_pixel7=gray_pixel7+coeff_result;
	        MulBlue7.apply(blue_M,blue_C7,coeff_result);;
	        gray_pixel7=gray_pixel7+coeff_result;

	        MulRed8.apply(red_M,red_C8,coeff_result);;
	        gray_pixel8=gray_pixel8+coeff_result;
	        MulGreen8.apply(green_M,green_C8,coeff_result);;						//using color information to convert to grayscale value for pixel 4
	        gray_pixel8=gray_pixel8+coeff_result;
	        MulBlue8.apply(blue_M,blue_C8,coeff_result);;
	        gray_pixel8=gray_pixel8+coeff_result;

	        MulRed9.apply(red_M,red_C9,coeff_result);;
	        gray_pixel9=gray_pixel9+coeff_result;
	        MulGreen9.apply(green_M,green_C9,coeff_result);;						//using color information to convert to grayscale value for pixel 4
	        gray_pixel9=gray_pixel9+coeff_result;
	        MulBlue9.apply(blue_M,blue_C9,coeff_result);;
	        gray_pixel9=gray_pixel9+coeff_result;


	        bit<4> floating=gray_pixel1[3:0];
	        gray_pixel1=gray_pixel1 >> 4;
	        if (floating >= 8) {
		    gray_pixel1=gray_pixel1+1;												//If fractional part for the value is above 0.5 (8 in fixed-point notation), ceiling is taken
	        }
	        if (gray_pixel1 > 255) gray_pixel1 = 32w255;
	    
	        floating=gray_pixel2[3:0];
	        gray_pixel2=gray_pixel2 >> 4;
	        if (floating >= 8) {
		    gray_pixel2=gray_pixel2+1;
	        }
	        if (gray_pixel2 > 255) gray_pixel2 = 32w255;

	        floating=gray_pixel3[3:0];
	        gray_pixel3=gray_pixel3 >> 4;
	        if (floating >= 8) {
		    gray_pixel3=gray_pixel3+1;
	        }
	        if (gray_pixel3 > 255) gray_pixel3 = 32w255;

	        floating=gray_pixel4[3:0];
	        gray_pixel4=gray_pixel4 >> 4;
	        if (floating >= 8) {
		    gray_pixel4=gray_pixel4+1;
	        }
	        if (gray_pixel4 > 255) gray_pixel4 = 32w255;

	        floating=gray_pixel5[3:0];
	        gray_pixel5=gray_pixel5 >> 4;
	        if (floating >= 8) {
		    gray_pixel5=gray_pixel5+1;
	        }
	        if (gray_pixel5 > 255) gray_pixel5 = 32w255;

	        floating=gray_pixel6[3:0];
	        gray_pixel6=gray_pixel6 >> 4;
	        if (floating >= 8) {
		    gray_pixel6=gray_pixel6+1;
	        }
	        if (gray_pixel6 > 255) gray_pixel6 = 32w255;

	        floating=gray_pixel7[3:0];
	        gray_pixel7=gray_pixel7 >> 4;
	        if (floating >= 8) {
		    gray_pixel7=gray_pixel7+1;
	        }
	        if (gray_pixel7 > 255) gray_pixel7 = 32w255;

	        floating=gray_pixel8[3:0];
	        gray_pixel8=gray_pixel8 >> 4;
	        if (floating >= 8) {
		    gray_pixel8=gray_pixel8+1;
	        }
	        if (gray_pixel8 > 255) gray_pixel8 = 32w255;

	        floating=gray_pixel9[3:0];
	        gray_pixel9=gray_pixel9 >> 4;
	        if (floating >= 8) {
		    gray_pixel9=gray_pixel9+1;
	        }
	        if (gray_pixel9 > 255) gray_pixel9 = 32w255;
            
            gray_bit_pixel1=gray_pixel1[7:0];
            gray_bit_pixel2=gray_pixel2[7:0];
            gray_bit_pixel3=gray_pixel3[7:0];
            gray_bit_pixel4=gray_pixel4[7:0];		//grayscale values, converted to binary 1 or 0 depending on whether they are > 128
            gray_bit_pixel5=gray_pixel5[7:0];
            gray_bit_pixel6=gray_pixel6[7:0];
            gray_bit_pixel7=gray_pixel7[7:0];
            gray_bit_pixel8=gray_pixel8[7:0];
            gray_bit_pixel9=gray_pixel9[7:0];

             bit<8> temp_weight=0;
	     bit<676> temp_response=0;
             bit<32> running_sum=32w0;   	
             bit<1> BResponse=0;

            
            
            //BWeighted.read(WeightedString,0);
            CNeuronRes1.read(temp_response,0);   				//retrieve the response values so far for this neuron
            CNeuron1.read(temp_weight,0); 		 				//read the binary weight for 1st pixel of 1st neuron
            CXNOR(temp_weight,gray_bit_pixel1); 				//XNOR operation
            CBitCount(CXNOROutput);								//popcount operation
            running_sum=running_sum+(bit<32>)CResponse; 		//note the reponse in the form of a running sum
            CNeuron1.read(temp_weight,1);
            CXNOR(temp_weight,gray_bit_pixel2);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron1.read(temp_weight,2);
            CXNOR(temp_weight,gray_bit_pixel3);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron1.read(temp_weight,3);
            CXNOR(temp_weight,gray_bit_pixel4);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron1.read(temp_weight,4);                                                   //Convolve all pixels of the chunk with filter of the first neuron
            CXNOR(temp_weight,gray_bit_pixel5);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron1.read(temp_weight,5);
            CXNOR(temp_weight,gray_bit_pixel6);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron1.read(temp_weight,6);
            CXNOR(temp_weight,gray_bit_pixel7);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron1.read(temp_weight,7);
            CXNOR(temp_weight,gray_bit_pixel8);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron1.read(temp_weight,8);
            CXNOR(temp_weight,gray_bit_pixel9);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            if (running_sum < 0) running_sum=0;                                             //Apply ReLU to remove negative values
            if (running_sum > B_threshold) BResponse=1;                                     //Check whether the value is above the threshold. Then set response as 1 else 0
            else BResponse=0;
	    temp_response=temp_response<<1;						//Shift the reponse value for this neuron thus far by 1
	    temp_response=temp_response+(bit<676>)BResponse;	//Add in the new reponse value
	    CNeuronRes1.write(0,temp_response);                                                  

		//The above continues for the rest of the neurons
            CNeuronRes2.read(temp_response,0);  
            CNeuron2.read(temp_weight,0);
            CXNOR(temp_weight,gray_bit_pixel1);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron2.read(temp_weight,1);
            CXNOR(temp_weight,gray_bit_pixel2);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron2.read(temp_weight,2);
            CXNOR(temp_weight,gray_bit_pixel3);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron2.read(temp_weight,3);
            CXNOR(temp_weight,gray_bit_pixel4);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron2.read(temp_weight,4);                                                   //Convolve all pixels of the chunk with filter of the first neuron
            CXNOR(temp_weight,gray_bit_pixel5);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron2.read(temp_weight,5);
            CXNOR(temp_weight,gray_bit_pixel6);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron2.read(temp_weight,6);
            CXNOR(temp_weight,gray_bit_pixel7);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron2.read(temp_weight,7);
            CXNOR(temp_weight,gray_bit_pixel8);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron2.read(temp_weight,8);
            CXNOR(temp_weight,gray_bit_pixel9);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            if (running_sum < 0) running_sum=0;
            if (running_sum > B_threshold) BResponse=1;
            else BResponse=0;
	    temp_response=temp_response<<1;
	    temp_response=temp_response+(bit<676>)BResponse;
	    CNeuronRes2.write(0,temp_response);   

            CNeuronRes3.read(temp_response,0);  
            CNeuron3.read(temp_weight,0);
            CXNOR(temp_weight,gray_bit_pixel1);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron3.read(temp_weight,1);
            CXNOR(temp_weight,gray_bit_pixel2);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron3.read(temp_weight,2);
            CXNOR(temp_weight,gray_bit_pixel3);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron3.read(temp_weight,3);
            CXNOR(temp_weight,gray_bit_pixel4);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron3.read(temp_weight,4);                                                   //Convolve all pixels of the chunk with filter of the first neuron
            CXNOR(temp_weight,gray_bit_pixel5);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron3.read(temp_weight,5);
            CXNOR(temp_weight,gray_bit_pixel6);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron3.read(temp_weight,6);
            CXNOR(temp_weight,gray_bit_pixel7);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron3.read(temp_weight,7);
            CXNOR(temp_weight,gray_bit_pixel8);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron3.read(temp_weight,8);
            CXNOR(temp_weight,gray_bit_pixel9);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            if (running_sum < 0) running_sum=0;
            if (running_sum > B_threshold) BResponse=1;
            else BResponse=0;
	    temp_response=temp_response<<1;
	    temp_response=temp_response+(bit<676>)BResponse;
	    CNeuronRes3.write(0,temp_response);   

            CNeuronRes4.read(temp_response,0);  
            CNeuron4.read(temp_weight,0);
            CXNOR(temp_weight,gray_bit_pixel1);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron4.read(temp_weight,1);
            CXNOR(temp_weight,gray_bit_pixel2);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron4.read(temp_weight,2);
            CXNOR(temp_weight,gray_bit_pixel3);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron4.read(temp_weight,3);
            CXNOR(temp_weight,gray_bit_pixel4);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron4.read(temp_weight,4);                                                   //Convolve all pixels of the chunk with filter of the first neuron
            CXNOR(temp_weight,gray_bit_pixel5);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron4.read(temp_weight,5);
            CXNOR(temp_weight,gray_bit_pixel6);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron4.read(temp_weight,6);
            CXNOR(temp_weight,gray_bit_pixel7);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron4.read(temp_weight,7);
            CXNOR(temp_weight,gray_bit_pixel8);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron4.read(temp_weight,8);
            CXNOR(temp_weight,gray_bit_pixel9);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            if (running_sum < 0) running_sum=0;
            if (running_sum > B_threshold) BResponse=1;
            else BResponse=0;
	    temp_response=temp_response<<1;
	    temp_response=temp_response+(bit<676>)BResponse;
	    CNeuronRes4.write(0,temp_response);   

            CNeuronRes5.read(temp_response,0);  
            CNeuron5.read(temp_weight,0);
            CXNOR(temp_weight,gray_bit_pixel1);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron5.read(temp_weight,1);
            CXNOR(temp_weight,gray_bit_pixel2);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron5.read(temp_weight,2);
            CXNOR(temp_weight,gray_bit_pixel3);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron5.read(temp_weight,3);
            CXNOR(temp_weight,gray_bit_pixel4);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron5.read(temp_weight,4);                                                   //Convolve all pixels of the chunk with filter of the first neuron
            CXNOR(temp_weight,gray_bit_pixel5);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron5.read(temp_weight,5);
            CXNOR(temp_weight,gray_bit_pixel6);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron5.read(temp_weight,6);
            CXNOR(temp_weight,gray_bit_pixel7);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron5.read(temp_weight,7);
            CXNOR(temp_weight,gray_bit_pixel8);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron5.read(temp_weight,8);
            CXNOR(temp_weight,gray_bit_pixel9);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            if (running_sum < 0) running_sum=0;
            if (running_sum > B_threshold) BResponse=1;
            else BResponse=0;
	    temp_response=temp_response<<1;
	    temp_response=temp_response+(bit<676>)BResponse;
	    CNeuronRes5.write(0,temp_response);   

            CNeuronRes6.read(temp_response,0);  
            CNeuron6.read(temp_weight,0);
            CXNOR(temp_weight,gray_bit_pixel1);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron6.read(temp_weight,1);
            CXNOR(temp_weight,gray_bit_pixel2);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron6.read(temp_weight,2);
            CXNOR(temp_weight,gray_bit_pixel3);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron6.read(temp_weight,3);
            CXNOR(temp_weight,gray_bit_pixel4);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron6.read(temp_weight,4);                                                   //Convolve all pixels of the chunk with filter of the first neuron
            CXNOR(temp_weight,gray_bit_pixel5);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron6.read(temp_weight,5);
            CXNOR(temp_weight,gray_bit_pixel6);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron6.read(temp_weight,6);
            CXNOR(temp_weight,gray_bit_pixel7);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron6.read(temp_weight,7);
            CXNOR(temp_weight,gray_bit_pixel8);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron6.read(temp_weight,8);
            CXNOR(temp_weight,gray_bit_pixel9);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            if (running_sum < 0) running_sum=0;
            if (running_sum > B_threshold) BResponse=1;
            else BResponse=0;
	    temp_response=temp_response<<1;
	    temp_response=temp_response+(bit<676>)BResponse;
	    CNeuronRes6.write(0,temp_response);   

            CNeuronRes7.read(temp_response,0);  
            CNeuron7.read(temp_weight,0);
            CXNOR(temp_weight,gray_bit_pixel1);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron7.read(temp_weight,1);
            CXNOR(temp_weight,gray_bit_pixel2);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron7.read(temp_weight,2);
            CXNOR(temp_weight,gray_bit_pixel3);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron7.read(temp_weight,3);
            CXNOR(temp_weight,gray_bit_pixel4);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron7.read(temp_weight,4);                                                   //Convolve all pixels of the chunk with filter of the first neuron
            CXNOR(temp_weight,gray_bit_pixel5);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron7.read(temp_weight,5);
            CXNOR(temp_weight,gray_bit_pixel6);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron7.read(temp_weight,6);
            CXNOR(temp_weight,gray_bit_pixel7);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron7.read(temp_weight,7);
            CXNOR(temp_weight,gray_bit_pixel8);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron7.read(temp_weight,8);
            CXNOR(temp_weight,gray_bit_pixel9);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            if (running_sum < 0) running_sum=0;
            if (running_sum > B_threshold) BResponse=1;
            else BResponse=0;
	    temp_response=temp_response<<1;
	    temp_response=temp_response+(bit<676>)BResponse;
	    CNeuronRes7.write(0,temp_response);   

            CNeuronRes8.read(temp_response,0);  
            CNeuron8.read(temp_weight,0);
            CXNOR(temp_weight,gray_bit_pixel1);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron8.read(temp_weight,1);
            CXNOR(temp_weight,gray_bit_pixel2);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron8.read(temp_weight,2);
            CXNOR(temp_weight,gray_bit_pixel3);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron8.read(temp_weight,3);
            CXNOR(temp_weight,gray_bit_pixel4);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron8.read(temp_weight,4);                                                   //Convolve all pixels of the chunk with filter of the first neuron
            CXNOR(temp_weight,gray_bit_pixel5);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron8.read(temp_weight,5);
            CXNOR(temp_weight,gray_bit_pixel6);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron8.read(temp_weight,6);
            CXNOR(temp_weight,gray_bit_pixel7);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron8.read(temp_weight,7);
            CXNOR(temp_weight,gray_bit_pixel8);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            CNeuron8.read(temp_weight,8);
            CXNOR(temp_weight,gray_bit_pixel9);
            CBitCount(CXNOROutput);
            running_sum=running_sum+(bit<32>)CResponse;
            if (running_sum < 0) running_sum=0;
            if (running_sum > B_threshold) BResponse=1;
            else BResponse=0;
	    temp_response=temp_response<<1;
	    temp_response=temp_response+(bit<676>)BResponse;
	    CNeuronRes8.write(0,temp_response);   

        }

		/* *********************************************** */
		/*                            AVG POOLING LAYER                        */
		/* ********************************************** */
	 else if (hdr.fcr.flag_value==2) {
		bit<676> carrier=0;
	        bit<169> response=0;
	        bit<4> avgstrres=0;
	        bit<169> bitadd=0;
	
		CNeuronRes1.read(carrier, 0);   						//take 2x2 neighborhood and find the average (if more than 2 pixels are 1, then 1 else 0
		hdr.fcr.CNeu1=carrier;
	        avgstrres=(bit<4>)carrier[675:675]+(bit<4>)carrier[674:674]+(bit<4>)carrier[649:649]+(bit<4>)carrier[648:648];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[673:673]+(bit<4>)carrier[672:672]+(bit<4>)carrier[647:647]+(bit<4>)carrier[646:646];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[671:671]+(bit<4>)carrier[670:670]+(bit<4>)carrier[645:645]+(bit<4>)carrier[644:644];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[669:669]+(bit<4>)carrier[668:668]+(bit<4>)carrier[643:643]+(bit<4>)carrier[642:642];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[667:667]+(bit<4>)carrier[666:666]+(bit<4>)carrier[641:641]+(bit<4>)carrier[640:640];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[665:665]+(bit<4>)carrier[664:664]+(bit<4>)carrier[639:639]+(bit<4>)carrier[638:638];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[663:663]+(bit<4>)carrier[662:662]+(bit<4>)carrier[637:637]+(bit<4>)carrier[636:636];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[661:661]+(bit<4>)carrier[660:660]+(bit<4>)carrier[635:635]+(bit<4>)carrier[634:634];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[659:659]+(bit<4>)carrier[658:658]+(bit<4>)carrier[633:633]+(bit<4>)carrier[632:632];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[657:657]+(bit<4>)carrier[656:656]+(bit<4>)carrier[631:631]+(bit<4>)carrier[630:630];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[655:655]+(bit<4>)carrier[654:654]+(bit<4>)carrier[629:629]+(bit<4>)carrier[628:628];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[653:653]+(bit<4>)carrier[652:652]+(bit<4>)carrier[627:627]+(bit<4>)carrier[626:626];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[651:651]+(bit<4>)carrier[650:650]+(bit<4>)carrier[625:625]+(bit<4>)carrier[624:624];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[623:623]+(bit<4>)carrier[622:622]+(bit<4>)carrier[597:597]+(bit<4>)carrier[596:596];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[621:621]+(bit<4>)carrier[620:620]+(bit<4>)carrier[595:595]+(bit<4>)carrier[594:594];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[619:619]+(bit<4>)carrier[618:618]+(bit<4>)carrier[593:593]+(bit<4>)carrier[592:592];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[617:617]+(bit<4>)carrier[616:616]+(bit<4>)carrier[591:591]+(bit<4>)carrier[590:590];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[615:615]+(bit<4>)carrier[614:614]+(bit<4>)carrier[589:589]+(bit<4>)carrier[588:588];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[613:613]+(bit<4>)carrier[612:612]+(bit<4>)carrier[587:587]+(bit<4>)carrier[586:586];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[611:611]+(bit<4>)carrier[610:610]+(bit<4>)carrier[585:585]+(bit<4>)carrier[584:584];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[609:609]+(bit<4>)carrier[608:608]+(bit<4>)carrier[583:583]+(bit<4>)carrier[582:582];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[607:607]+(bit<4>)carrier[606:606]+(bit<4>)carrier[581:581]+(bit<4>)carrier[580:580];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[605:605]+(bit<4>)carrier[604:604]+(bit<4>)carrier[579:579]+(bit<4>)carrier[578:578];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[603:603]+(bit<4>)carrier[602:602]+(bit<4>)carrier[577:577]+(bit<4>)carrier[576:576];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[601:601]+(bit<4>)carrier[600:600]+(bit<4>)carrier[575:575]+(bit<4>)carrier[574:574];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[599:599]+(bit<4>)carrier[598:598]+(bit<4>)carrier[573:573]+(bit<4>)carrier[572:572];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[571:571]+(bit<4>)carrier[570:570]+(bit<4>)carrier[545:545]+(bit<4>)carrier[544:544];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[569:569]+(bit<4>)carrier[568:568]+(bit<4>)carrier[543:543]+(bit<4>)carrier[542:542];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[567:567]+(bit<4>)carrier[566:566]+(bit<4>)carrier[541:541]+(bit<4>)carrier[540:540];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[565:565]+(bit<4>)carrier[564:564]+(bit<4>)carrier[539:539]+(bit<4>)carrier[538:538];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[563:563]+(bit<4>)carrier[562:562]+(bit<4>)carrier[537:537]+(bit<4>)carrier[536:536];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[561:561]+(bit<4>)carrier[560:560]+(bit<4>)carrier[535:535]+(bit<4>)carrier[534:534];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[559:559]+(bit<4>)carrier[558:558]+(bit<4>)carrier[533:533]+(bit<4>)carrier[532:532];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[557:557]+(bit<4>)carrier[556:556]+(bit<4>)carrier[531:531]+(bit<4>)carrier[530:530];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[555:555]+(bit<4>)carrier[554:554]+(bit<4>)carrier[529:529]+(bit<4>)carrier[528:528];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[553:553]+(bit<4>)carrier[552:552]+(bit<4>)carrier[527:527]+(bit<4>)carrier[526:526];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[551:551]+(bit<4>)carrier[550:550]+(bit<4>)carrier[525:525]+(bit<4>)carrier[524:524];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[549:549]+(bit<4>)carrier[548:548]+(bit<4>)carrier[523:523]+(bit<4>)carrier[522:522];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[547:547]+(bit<4>)carrier[546:546]+(bit<4>)carrier[521:521]+(bit<4>)carrier[520:520];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[519:519]+(bit<4>)carrier[518:518]+(bit<4>)carrier[493:493]+(bit<4>)carrier[492:492];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[517:517]+(bit<4>)carrier[516:516]+(bit<4>)carrier[491:491]+(bit<4>)carrier[490:490];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[515:515]+(bit<4>)carrier[514:514]+(bit<4>)carrier[489:489]+(bit<4>)carrier[488:488];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[513:513]+(bit<4>)carrier[512:512]+(bit<4>)carrier[487:487]+(bit<4>)carrier[486:486];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[511:511]+(bit<4>)carrier[510:510]+(bit<4>)carrier[485:485]+(bit<4>)carrier[484:484];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[509:509]+(bit<4>)carrier[508:508]+(bit<4>)carrier[483:483]+(bit<4>)carrier[482:482];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[507:507]+(bit<4>)carrier[506:506]+(bit<4>)carrier[481:481]+(bit<4>)carrier[480:480];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[505:505]+(bit<4>)carrier[504:504]+(bit<4>)carrier[479:479]+(bit<4>)carrier[478:478];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[503:503]+(bit<4>)carrier[502:502]+(bit<4>)carrier[477:477]+(bit<4>)carrier[476:476];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[501:501]+(bit<4>)carrier[500:500]+(bit<4>)carrier[475:475]+(bit<4>)carrier[474:474];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[499:499]+(bit<4>)carrier[498:498]+(bit<4>)carrier[473:473]+(bit<4>)carrier[472:472];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[497:497]+(bit<4>)carrier[496:496]+(bit<4>)carrier[471:471]+(bit<4>)carrier[470:470];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[495:495]+(bit<4>)carrier[494:494]+(bit<4>)carrier[469:469]+(bit<4>)carrier[468:468];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[467:467]+(bit<4>)carrier[466:466]+(bit<4>)carrier[441:441]+(bit<4>)carrier[440:440];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[465:465]+(bit<4>)carrier[464:464]+(bit<4>)carrier[439:439]+(bit<4>)carrier[438:438];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[463:463]+(bit<4>)carrier[462:462]+(bit<4>)carrier[437:437]+(bit<4>)carrier[436:436];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[461:461]+(bit<4>)carrier[460:460]+(bit<4>)carrier[435:435]+(bit<4>)carrier[434:434];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[459:459]+(bit<4>)carrier[458:458]+(bit<4>)carrier[433:433]+(bit<4>)carrier[432:432];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[457:457]+(bit<4>)carrier[456:456]+(bit<4>)carrier[431:431]+(bit<4>)carrier[430:430];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[455:455]+(bit<4>)carrier[454:454]+(bit<4>)carrier[429:429]+(bit<4>)carrier[428:428];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[453:453]+(bit<4>)carrier[452:452]+(bit<4>)carrier[427:427]+(bit<4>)carrier[426:426];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[451:451]+(bit<4>)carrier[450:450]+(bit<4>)carrier[425:425]+(bit<4>)carrier[424:424];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[449:449]+(bit<4>)carrier[448:448]+(bit<4>)carrier[423:423]+(bit<4>)carrier[422:422];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[447:447]+(bit<4>)carrier[446:446]+(bit<4>)carrier[421:421]+(bit<4>)carrier[420:420];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[445:445]+(bit<4>)carrier[444:444]+(bit<4>)carrier[419:419]+(bit<4>)carrier[418:418];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[443:443]+(bit<4>)carrier[442:442]+(bit<4>)carrier[417:417]+(bit<4>)carrier[416:416];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[415:415]+(bit<4>)carrier[414:414]+(bit<4>)carrier[389:389]+(bit<4>)carrier[388:388];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[413:413]+(bit<4>)carrier[412:412]+(bit<4>)carrier[387:387]+(bit<4>)carrier[386:386];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[411:411]+(bit<4>)carrier[410:410]+(bit<4>)carrier[385:385]+(bit<4>)carrier[384:384];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[409:409]+(bit<4>)carrier[408:408]+(bit<4>)carrier[383:383]+(bit<4>)carrier[382:382];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[407:407]+(bit<4>)carrier[406:406]+(bit<4>)carrier[381:381]+(bit<4>)carrier[380:380];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[405:405]+(bit<4>)carrier[404:404]+(bit<4>)carrier[379:379]+(bit<4>)carrier[378:378];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[403:403]+(bit<4>)carrier[402:402]+(bit<4>)carrier[377:377]+(bit<4>)carrier[376:376];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[401:401]+(bit<4>)carrier[400:400]+(bit<4>)carrier[375:375]+(bit<4>)carrier[374:374];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[399:399]+(bit<4>)carrier[398:398]+(bit<4>)carrier[373:373]+(bit<4>)carrier[372:372];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[397:397]+(bit<4>)carrier[396:396]+(bit<4>)carrier[371:371]+(bit<4>)carrier[370:370];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[395:395]+(bit<4>)carrier[394:394]+(bit<4>)carrier[369:369]+(bit<4>)carrier[368:368];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[393:393]+(bit<4>)carrier[392:392]+(bit<4>)carrier[367:367]+(bit<4>)carrier[366:366];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[391:391]+(bit<4>)carrier[390:390]+(bit<4>)carrier[365:365]+(bit<4>)carrier[364:364];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[363:363]+(bit<4>)carrier[362:362]+(bit<4>)carrier[337:337]+(bit<4>)carrier[336:336];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[361:361]+(bit<4>)carrier[360:360]+(bit<4>)carrier[335:335]+(bit<4>)carrier[334:334];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[359:359]+(bit<4>)carrier[358:358]+(bit<4>)carrier[333:333]+(bit<4>)carrier[332:332];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[357:357]+(bit<4>)carrier[356:356]+(bit<4>)carrier[331:331]+(bit<4>)carrier[330:330];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[355:355]+(bit<4>)carrier[354:354]+(bit<4>)carrier[329:329]+(bit<4>)carrier[328:328];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[353:353]+(bit<4>)carrier[352:352]+(bit<4>)carrier[327:327]+(bit<4>)carrier[326:326];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[351:351]+(bit<4>)carrier[350:350]+(bit<4>)carrier[325:325]+(bit<4>)carrier[324:324];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[349:349]+(bit<4>)carrier[348:348]+(bit<4>)carrier[323:323]+(bit<4>)carrier[322:322];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[347:347]+(bit<4>)carrier[346:346]+(bit<4>)carrier[321:321]+(bit<4>)carrier[320:320];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[345:345]+(bit<4>)carrier[344:344]+(bit<4>)carrier[319:319]+(bit<4>)carrier[318:318];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[343:343]+(bit<4>)carrier[342:342]+(bit<4>)carrier[317:317]+(bit<4>)carrier[316:316];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[341:341]+(bit<4>)carrier[340:340]+(bit<4>)carrier[315:315]+(bit<4>)carrier[314:314];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[339:339]+(bit<4>)carrier[338:338]+(bit<4>)carrier[313:313]+(bit<4>)carrier[312:312];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[311:311]+(bit<4>)carrier[310:310]+(bit<4>)carrier[285:285]+(bit<4>)carrier[284:284];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[309:309]+(bit<4>)carrier[308:308]+(bit<4>)carrier[283:283]+(bit<4>)carrier[282:282];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[307:307]+(bit<4>)carrier[306:306]+(bit<4>)carrier[281:281]+(bit<4>)carrier[280:280];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[305:305]+(bit<4>)carrier[304:304]+(bit<4>)carrier[279:279]+(bit<4>)carrier[278:278];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[303:303]+(bit<4>)carrier[302:302]+(bit<4>)carrier[277:277]+(bit<4>)carrier[276:276];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[301:301]+(bit<4>)carrier[300:300]+(bit<4>)carrier[275:275]+(bit<4>)carrier[274:274];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[299:299]+(bit<4>)carrier[298:298]+(bit<4>)carrier[273:273]+(bit<4>)carrier[272:272];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[297:297]+(bit<4>)carrier[296:296]+(bit<4>)carrier[271:271]+(bit<4>)carrier[270:270];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[295:295]+(bit<4>)carrier[294:294]+(bit<4>)carrier[269:269]+(bit<4>)carrier[268:268];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[293:293]+(bit<4>)carrier[292:292]+(bit<4>)carrier[267:267]+(bit<4>)carrier[266:266];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[291:291]+(bit<4>)carrier[290:290]+(bit<4>)carrier[265:265]+(bit<4>)carrier[264:264];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[289:289]+(bit<4>)carrier[288:288]+(bit<4>)carrier[263:263]+(bit<4>)carrier[262:262];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[287:287]+(bit<4>)carrier[286:286]+(bit<4>)carrier[261:261]+(bit<4>)carrier[260:260];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[259:259]+(bit<4>)carrier[258:258]+(bit<4>)carrier[233:233]+(bit<4>)carrier[232:232];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[257:257]+(bit<4>)carrier[256:256]+(bit<4>)carrier[231:231]+(bit<4>)carrier[230:230];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[255:255]+(bit<4>)carrier[254:254]+(bit<4>)carrier[229:229]+(bit<4>)carrier[228:228];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[253:253]+(bit<4>)carrier[252:252]+(bit<4>)carrier[227:227]+(bit<4>)carrier[226:226];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[251:251]+(bit<4>)carrier[250:250]+(bit<4>)carrier[225:225]+(bit<4>)carrier[224:224];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[249:249]+(bit<4>)carrier[248:248]+(bit<4>)carrier[223:223]+(bit<4>)carrier[222:222];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[247:247]+(bit<4>)carrier[246:246]+(bit<4>)carrier[221:221]+(bit<4>)carrier[220:220];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[245:245]+(bit<4>)carrier[244:244]+(bit<4>)carrier[219:219]+(bit<4>)carrier[218:218];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[243:243]+(bit<4>)carrier[242:242]+(bit<4>)carrier[217:217]+(bit<4>)carrier[216:216];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[241:241]+(bit<4>)carrier[240:240]+(bit<4>)carrier[215:215]+(bit<4>)carrier[214:214];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[239:239]+(bit<4>)carrier[238:238]+(bit<4>)carrier[213:213]+(bit<4>)carrier[212:212];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[237:237]+(bit<4>)carrier[236:236]+(bit<4>)carrier[211:211]+(bit<4>)carrier[210:210];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[235:235]+(bit<4>)carrier[234:234]+(bit<4>)carrier[209:209]+(bit<4>)carrier[208:208];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[207:207]+(bit<4>)carrier[206:206]+(bit<4>)carrier[181:181]+(bit<4>)carrier[180:180];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[205:205]+(bit<4>)carrier[204:204]+(bit<4>)carrier[179:179]+(bit<4>)carrier[178:178];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[203:203]+(bit<4>)carrier[202:202]+(bit<4>)carrier[177:177]+(bit<4>)carrier[176:176];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[201:201]+(bit<4>)carrier[200:200]+(bit<4>)carrier[175:175]+(bit<4>)carrier[174:174];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[199:199]+(bit<4>)carrier[198:198]+(bit<4>)carrier[173:173]+(bit<4>)carrier[172:172];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[197:197]+(bit<4>)carrier[196:196]+(bit<4>)carrier[171:171]+(bit<4>)carrier[170:170];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[195:195]+(bit<4>)carrier[194:194]+(bit<4>)carrier[169:169]+(bit<4>)carrier[168:168];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[193:193]+(bit<4>)carrier[192:192]+(bit<4>)carrier[167:167]+(bit<4>)carrier[166:166];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[191:191]+(bit<4>)carrier[190:190]+(bit<4>)carrier[165:165]+(bit<4>)carrier[164:164];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[189:189]+(bit<4>)carrier[188:188]+(bit<4>)carrier[163:163]+(bit<4>)carrier[162:162];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[187:187]+(bit<4>)carrier[186:186]+(bit<4>)carrier[161:161]+(bit<4>)carrier[160:160];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[185:185]+(bit<4>)carrier[184:184]+(bit<4>)carrier[159:159]+(bit<4>)carrier[158:158];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[183:183]+(bit<4>)carrier[182:182]+(bit<4>)carrier[157:157]+(bit<4>)carrier[156:156];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[155:155]+(bit<4>)carrier[154:154]+(bit<4>)carrier[129:129]+(bit<4>)carrier[128:128];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[153:153]+(bit<4>)carrier[152:152]+(bit<4>)carrier[127:127]+(bit<4>)carrier[126:126];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[151:151]+(bit<4>)carrier[150:150]+(bit<4>)carrier[125:125]+(bit<4>)carrier[124:124];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[149:149]+(bit<4>)carrier[148:148]+(bit<4>)carrier[123:123]+(bit<4>)carrier[122:122];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[147:147]+(bit<4>)carrier[146:146]+(bit<4>)carrier[121:121]+(bit<4>)carrier[120:120];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[145:145]+(bit<4>)carrier[144:144]+(bit<4>)carrier[119:119]+(bit<4>)carrier[118:118];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[143:143]+(bit<4>)carrier[142:142]+(bit<4>)carrier[117:117]+(bit<4>)carrier[116:116];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[141:141]+(bit<4>)carrier[140:140]+(bit<4>)carrier[115:115]+(bit<4>)carrier[114:114];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[139:139]+(bit<4>)carrier[138:138]+(bit<4>)carrier[113:113]+(bit<4>)carrier[112:112];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[137:137]+(bit<4>)carrier[136:136]+(bit<4>)carrier[111:111]+(bit<4>)carrier[110:110];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[135:135]+(bit<4>)carrier[134:134]+(bit<4>)carrier[109:109]+(bit<4>)carrier[108:108];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[133:133]+(bit<4>)carrier[132:132]+(bit<4>)carrier[107:107]+(bit<4>)carrier[106:106];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[131:131]+(bit<4>)carrier[130:130]+(bit<4>)carrier[105:105]+(bit<4>)carrier[104:104];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[103:103]+(bit<4>)carrier[102:102]+(bit<4>)carrier[77:77]+(bit<4>)carrier[76:76];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[101:101]+(bit<4>)carrier[100:100]+(bit<4>)carrier[75:75]+(bit<4>)carrier[74:74];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[99:99]+(bit<4>)carrier[98:98]+(bit<4>)carrier[73:73]+(bit<4>)carrier[72:72];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[97:97]+(bit<4>)carrier[96:96]+(bit<4>)carrier[71:71]+(bit<4>)carrier[70:70];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[95:95]+(bit<4>)carrier[94:94]+(bit<4>)carrier[69:69]+(bit<4>)carrier[68:68];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[93:93]+(bit<4>)carrier[92:92]+(bit<4>)carrier[67:67]+(bit<4>)carrier[66:66];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[91:91]+(bit<4>)carrier[90:90]+(bit<4>)carrier[65:65]+(bit<4>)carrier[64:64];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[89:89]+(bit<4>)carrier[88:88]+(bit<4>)carrier[63:63]+(bit<4>)carrier[62:62];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[87:87]+(bit<4>)carrier[86:86]+(bit<4>)carrier[61:61]+(bit<4>)carrier[60:60];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[85:85]+(bit<4>)carrier[84:84]+(bit<4>)carrier[59:59]+(bit<4>)carrier[58:58];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[83:83]+(bit<4>)carrier[82:82]+(bit<4>)carrier[57:57]+(bit<4>)carrier[56:56];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[81:81]+(bit<4>)carrier[80:80]+(bit<4>)carrier[55:55]+(bit<4>)carrier[54:54];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[79:79]+(bit<4>)carrier[78:78]+(bit<4>)carrier[53:53]+(bit<4>)carrier[52:52];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[51:51]+(bit<4>)carrier[50:50]+(bit<4>)carrier[25:25]+(bit<4>)carrier[24:24];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[49:49]+(bit<4>)carrier[48:48]+(bit<4>)carrier[23:23]+(bit<4>)carrier[22:22];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[47:47]+(bit<4>)carrier[46:46]+(bit<4>)carrier[21:21]+(bit<4>)carrier[20:20];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[45:45]+(bit<4>)carrier[44:44]+(bit<4>)carrier[19:19]+(bit<4>)carrier[18:18];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[43:43]+(bit<4>)carrier[42:42]+(bit<4>)carrier[17:17]+(bit<4>)carrier[16:16];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[41:41]+(bit<4>)carrier[40:40]+(bit<4>)carrier[15:15]+(bit<4>)carrier[14:14];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[39:39]+(bit<4>)carrier[38:38]+(bit<4>)carrier[13:13]+(bit<4>)carrier[12:12];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[37:37]+(bit<4>)carrier[36:36]+(bit<4>)carrier[11:11]+(bit<4>)carrier[10:10];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[35:35]+(bit<4>)carrier[34:34]+(bit<4>)carrier[9:9]+(bit<4>)carrier[8:8];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[33:33]+(bit<4>)carrier[32:32]+(bit<4>)carrier[7:7]+(bit<4>)carrier[6:6];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[31:31]+(bit<4>)carrier[30:30]+(bit<4>)carrier[5:5]+(bit<4>)carrier[4:4];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[29:29]+(bit<4>)carrier[28:28]+(bit<4>)carrier[3:3]+(bit<4>)carrier[2:2];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        avgstrres=(bit<4>)carrier[27:27]+(bit<4>)carrier[26:26]+(bit<4>)carrier[1:1]+(bit<4>)carrier[0:0];
	        if (avgstrres>=2){
	            bitadd=1;
	        }
	        else{
	            bitadd=0;
	        }
	        response=response<<1;
	        response=response+bitadd;
	        hdr.fcr.CNeuronRes=response;
	        response=0;
		standard_metadata.egress_spec=2;  
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

