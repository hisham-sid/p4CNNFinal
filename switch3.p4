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

	register<bit<81>>(64) FCWeight1;
	register<bit<81>>(64) FCWeight2;
	register<bit<81>>(64) FCWeight3;
	register<bit<81>>(64) FCWeight4;
	
	
	register<bit<4>>(1) OWeight1;
	register<bit<4>>(1) OWeight2;
	


    bit<128> m1 = 0x55555555555555555555555555555555;
    bit<128> m2 = 0x33333333333333333333333333333333;
    bit<128> m4 = 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f;
    bit<128> m8 = 0x00ff00ff00ff00ff00ff00ff00ff00ff;
    bit<128> m16= 0x0000ffff0000ffff0000ffff0000ffff;
    bit<128> m32= 0x00000000ffffffff00000000ffffffff;
    bit<128> m64= 0x0000000000000000ffffffffffffffff;


    bit<81> CXNOROutput=0;					 //output of XNOR for the Convolutional layer					
    bit<1> CResponse=0;						 //convolutional response for each xnor-popcount operation
    bit<8> activated=0;
    bit<32> final_class=32w0;
	bit<1> BResponse=0;
	bit<4> OXNOROutput=0;


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

	/XNOR, involving 81-bit operands
    action CXNOR(bit<81> weight, bit<81> pixel){
        CXNOROutput = weight^pixel;
        CXNOROutput = ~CXNOROutput;
    }
	//popcount
    action CBitCount(bit<81> bitInput){
	bit<128> x= (bit<128>)bitInput;
	x = (x & m1 ) + ((x >>  1) & m1 ); 
	x = (x & m2 ) + ((x >>  2) & m2 );
	x = (x & m4 ) + ((x >>  4) & m4 );
    x = (x & m8 ) + ((x >>  8) & m8 );
    x = (x & m16) + ((x >> 16) & m16);
	x = (x & m32) + ((x >> 32) & m32);
	x = (x & m64) + ((x >> 64) & m64);
	if (x>40) CResponse = 1;
	else CResponse = 0;
    }
	//XNOR for output layer
	 action OXNOR(bit<4> weight, bit<4> pixel){
        OXNOROutput = weight^pixel;
        OXNOROutput = ~OXNOROutput;
    }

	//Output layer popcount
    action BBitCount(bit<64> bitInput){
	bit<128> x= (bit<128>)bitInput;
	x = (x & m1 ) + ((x >>  1) & m1 ); 
	x = (x & m2 ) + ((x >>  2) & m2 );
	x = (x & m4 ) + ((x >>  4) & m4 );
    x = (x & m8 ) + ((x >>  8) & m8 );
    x = (x & m16) + ((x >> 16) & m16);
	x = (x & m32) + ((x >> 32) & m32);
	if (x>32) BResponse = 1;
	else BResponse = 0;
    }

     
    apply {
		
		bit<81> temp_weight=0;
		bit<64> temp_result=0;
		
		bit<64> temp_f1=0;
		bit<64> temp_f2=0;
		bit<64> temp_f3=0;
		bit<64> temp_f4=0;
		
		bit<1> final_f1=0;
		bit<1> final_f2=0;
		bit<1> final_f3=0;
		bit<1> final_f4=0;
		
		FCWeight1.write(0,1751180521533295789174557);			//write weight values
		FCWeight1.write(1,153779206232016362453101);
		FCWeight1.write(2,2301310821963009890860151);
		FCWeight1.write(3,1859031755134230056077925);
		FCWeight1.write(4,1263929023772293076466462);
		FCWeight1.write(5,1248749068204057811626617);
		FCWeight1.write(6,2404099918197319254709826);
		FCWeight1.write(7,485073381427413410105606);
		FCWeight1.write(8,1531872222213612712255791);
		FCWeight1.write(9,111969805828154688480388);
		FCWeight1.write(10,975529488447392257173574);
		FCWeight1.write(11,268657842259523329080882);
		FCWeight1.write(12,1803435700259722575204933);
		FCWeight1.write(13,945494179352137600002061);
		FCWeight1.write(14,1162606107903695549053298);
		FCWeight1.write(15,1725741212400367763762072);
		FCWeight1.write(16,1471873051277103648967991);
		FCWeight1.write(17,253037196793708663474678);
		FCWeight1.write(18,388183346258836435568716);
		FCWeight1.write(19,2044551997575366748087572);
		FCWeight1.write(20,497061859635498593511980);
		FCWeight1.write(21,104142042075374832677927);
		FCWeight1.write(22,2314753706462774899330730);
		FCWeight1.write(23,1026566660818923497932548);
		FCWeight1.write(24,2152268684472405608850642);
		FCWeight1.write(25,1868089266889461011878899);
		FCWeight1.write(26,1180128424043015660990182);
		FCWeight1.write(27,2056484177709298598297091);
		FCWeight1.write(28,2311460340853157934755831);
		FCWeight1.write(29,2222919660456433111342382);
		FCWeight1.write(30,621190790961178288916520);
		FCWeight1.write(31,1138200516628462431745159);
		FCWeight1.write(32,1448674697668924922589180);
		FCWeight1.write(33,1511619085496102460375668);
		FCWeight1.write(34,1085439843228770426708350);
		FCWeight1.write(35,374208599077661692781691);
		FCWeight1.write(36,1357239511563065519152996);
		FCWeight1.write(37,1789759551169896147611149);
		FCWeight1.write(38,1067536695412726627659860);
		FCWeight1.write(39,1677214778438045759871547);
		FCWeight1.write(40,204232987848507112646085);
		FCWeight1.write(41,799917374346640488718008);
		FCWeight1.write(42,597040044513317460150289);
		FCWeight1.write(43,2318517660165021137418434);
		FCWeight1.write(44,1682427315622655869503039);
		FCWeight1.write(45,478909149461219460491854);
		FCWeight1.write(46,769177818722662442760397);
		FCWeight1.write(47,757253091237287370029041);
		FCWeight1.write(48,252945968542117258905356);
		FCWeight1.write(49,574115847084139234164865);
		FCWeight1.write(50,655727062437341289200338);
		FCWeight1.write(51,577715394759614481558726);
		FCWeight1.write(52,1150005408468308398066771);
		FCWeight1.write(53,763964342321841820858791);
		FCWeight1.write(54,1750066914226164491091542);
		FCWeight1.write(55,84519951493231632670416);
		FCWeight1.write(56,620041454640987051908769);
		FCWeight1.write(57,626744617043657216480089);
		FCWeight1.write(58,62788737674556657669624);
		FCWeight1.write(59,2103931318972220462131822);
		FCWeight1.write(60,290743450958319880186546);
		FCWeight1.write(61,2264674871588579636352967);
		FCWeight1.write(62,370890890861133976992483);
		FCWeight1.write(63,820787341449586242305288);
		FCWeight2.write(0,535853751279856446277756);
		FCWeight2.write(1,800121350453358885699157);
		FCWeight2.write(2,41463802485303891786084);
		FCWeight2.write(3,2168279480873959569640073);
		FCWeight2.write(4,1128204246793313352519930);
		FCWeight2.write(5,683507765355913125339538);
		FCWeight2.write(6,71789611881669231317094);
		FCWeight2.write(7,524533403223291364425145);
		FCWeight2.write(8,372070374579040704493163);
		FCWeight2.write(9,1735779129019986849254410);
		FCWeight2.write(10,440602577235970847390881);
		FCWeight2.write(11,26118719456504060940799);
		FCWeight2.write(12,347541837204458473216625);
		FCWeight2.write(13,1647069070548440594909314);
		FCWeight2.write(14,1080176219930177345855365);
		FCWeight2.write(15,1915968392733774741432696);
		FCWeight2.write(16,1007054755990740977490745);
		FCWeight2.write(17,164251301860626607121590);
		FCWeight2.write(18,1052603422038172605516569);
		FCWeight2.write(19,137423918021041554099982);
		FCWeight2.write(20,72025908362150054414477);
		FCWeight2.write(21,2127003123820445438504534);
		FCWeight2.write(22,1956745470751510632065059);
		FCWeight2.write(23,1373345976943834804711912);
		FCWeight2.write(24,2057958741903517195560370);
		FCWeight2.write(25,28260873000074192100951);
		FCWeight2.write(26,490303770221574765151815);
		FCWeight2.write(27,291797051353320526460151);
		FCWeight2.write(28,1368813642806274184567003);
		FCWeight2.write(29,2199779578913122930608394);
		FCWeight2.write(30,2280354296529809566288450);
		FCWeight2.write(31,2107330850569695688753796);
		FCWeight2.write(32,2255274120772674826641035);
		FCWeight2.write(33,2072343532065590064673623);
		FCWeight2.write(34,1688871556134355970119238);
		FCWeight2.write(35,2308276392129036410466253);
		FCWeight2.write(36,2294684935023871592336851);
		FCWeight2.write(37,874552735982635071304028);
		FCWeight2.write(38,1212302799582018538904777);
		FCWeight2.write(39,1303165434090070400674239);
		FCWeight2.write(40,1402493607563909656934507);
		FCWeight2.write(41,1883228666554936022918162);
		FCWeight2.write(42,2295906189192862799855120);
		FCWeight2.write(43,1481683320036199045448594);
		FCWeight2.write(44,30420182212934495674720);
		FCWeight2.write(45,1152068627157281358096386);
		FCWeight2.write(46,1636416856772026423315646);
		FCWeight2.write(47,274764336987291346628112);
		FCWeight2.write(48,3866046203905898014467);
		FCWeight2.write(49,1817141338387976381928950);
		FCWeight2.write(50,308088769553569316125609);
		FCWeight2.write(51,189553639181175154100335);
		FCWeight2.write(52,1663813780980750431194654);
		FCWeight2.write(53,1062746276872557854388114);
		FCWeight2.write(54,1055987535593598707971524);
		FCWeight2.write(55,855842645661061806693066);
		FCWeight2.write(56,1583794397962924013075494);
		FCWeight2.write(57,818330944321830265241980);
		FCWeight2.write(58,41437953593305511912015);
		FCWeight2.write(59,1126628405689136537783161);
		FCWeight2.write(60,2376438191429115080358095);
		FCWeight2.write(61,1615662887431120108216698);
		FCWeight2.write(62,1986475751042219244875019);
		FCWeight2.write(63,243357409333658153751628);
		FCWeight3.write(0,707894479733710186619993);
		FCWeight3.write(1,275246457783475780140761);
		FCWeight3.write(2,1226598191517086274836248);
		FCWeight3.write(3,1671446450070774200649885);
		FCWeight3.write(4,2298676297572117334366100);
		FCWeight3.write(5,228723947385941365338176);
		FCWeight3.write(6,1648197470275976168761230);
		FCWeight3.write(7,1183230260498064227750807);
		FCWeight3.write(8,1215738206219723157676626);
		FCWeight3.write(9,709416488088526041509152);
		FCWeight3.write(10,880899632868246977928049);
		FCWeight3.write(11,205785971603961038843227);
		FCWeight3.write(12,1665657567829722198595708);
		FCWeight3.write(13,1804199123694834412431661);
		FCWeight3.write(14,445102465532182048676352);
		FCWeight3.write(15,2013048218025275787115024);
		FCWeight3.write(16,1249979056032818339292043);
		FCWeight3.write(17,1978304939589020751303375);
		FCWeight3.write(18,1449354920718384508092052);
		FCWeight3.write(19,1816655225217245331354084);
		FCWeight3.write(20,1488427381120430862753168);
		FCWeight3.write(21,2416430212998091519198770);
		FCWeight3.write(22,1163388682381716897970604);
		FCWeight3.write(23,1868728600536133278533170);
		FCWeight3.write(24,1672244687562186695644352);
		FCWeight3.write(25,2324555098928702877648895);
		FCWeight3.write(26,1536837751847870338277014);
		FCWeight3.write(27,228530277065364531214972);
		FCWeight3.write(28,1058298651024987811394285);
		FCWeight3.write(29,1928324348625769961163239);
		FCWeight3.write(30,2254921209158278331786058);
		FCWeight3.write(31,2375888257045283404777539);
		FCWeight3.write(32,885786412979834142905686);
		FCWeight3.write(33,14448701937819456885178);
		FCWeight3.write(34,168954250178418315314533);
		FCWeight3.write(35,267913036155667159609772);
		FCWeight3.write(36,621381649983913903344965);
		FCWeight3.write(37,568875124054699418094342);
		FCWeight3.write(38,392076108418811563230331);
		FCWeight3.write(39,414234836636993490169236);
		FCWeight3.write(40,977316639996804335956441);
		FCWeight3.write(41,233206536359468099601810);
		FCWeight3.write(42,1631030221280838864207442);
		FCWeight3.write(43,936259410980937768735949);
		FCWeight3.write(44,988433522782905680752270);
		FCWeight3.write(45,401450629724547315366738);
		FCWeight3.write(46,1016670716746507041789827);
		FCWeight3.write(47,767020214038026750008015);
		FCWeight3.write(48,2212493068479400249276208);
		FCWeight3.write(49,2209647954368726664920909);
		FCWeight3.write(50,2203690910922452521361392);
		FCWeight3.write(51,2144198268223751574293538);
		FCWeight3.write(52,810392139029188396979448);
		FCWeight3.write(53,2057810448562062632658204);
		FCWeight3.write(54,1316895216056450329293654);
		FCWeight3.write(55,488822605428187728533992);
		FCWeight3.write(56,1097042791373697877631370);
		FCWeight3.write(57,2238638291964802966346925);
		FCWeight3.write(58,1183952771663881314444437);
		FCWeight3.write(59,1414440393597974455888206);
		FCWeight3.write(60,1784925372121430497472326);
		FCWeight3.write(61,463577954156253976838606);
		FCWeight3.write(62,938148638111112123635030);
		FCWeight3.write(63,1389698154819815063735929);
		FCWeight4.write(0,849223292101950582802289);
		FCWeight4.write(1,497953980650728249152727);
		FCWeight4.write(2,1442013529701345434253177);
		FCWeight4.write(3,1617588383112227274133078);
		FCWeight4.write(4,271272189921894866986296);
		FCWeight4.write(5,1760872187087544824395075);
		FCWeight4.write(6,1381068801311229099158261);
		FCWeight4.write(7,1839634042306828147741268);
		FCWeight4.write(8,1345417075503563506480317);
		FCWeight4.write(9,267134082122978379289877);
		FCWeight4.write(10,707173240359706114744654);
		FCWeight4.write(11,118082336754246317967219);
		FCWeight4.write(12,462504659970869482385338);
		FCWeight4.write(13,1642815244043606858026250);
		FCWeight4.write(14,1166558693736423020558163);
		FCWeight4.write(15,1033866597337380300896490);
		FCWeight4.write(16,466216536571383964461987);
		FCWeight4.write(17,1270911241984420099978368);
		FCWeight4.write(18,483807277523616873031781);
		FCWeight4.write(19,1329532930053615378689062);
		FCWeight4.write(20,2161078025717115331306525);
		FCWeight4.write(21,792337846418449454212505);
		FCWeight4.write(22,2400226122628114555953413);
		FCWeight4.write(23,1021132944568300816599344);
		FCWeight4.write(24,1308895820276334579159526);
		FCWeight4.write(25,1145771477264594971309349);
		FCWeight4.write(26,2013824370978629443967318);
		FCWeight4.write(27,605552433520871503930185);
		FCWeight4.write(28,1951046043313617606250147);
		FCWeight4.write(29,1033776729555535289856529);
		FCWeight4.write(30,2045930519158673235776944);
		FCWeight4.write(31,1796568394404267643538759);
		FCWeight4.write(32,2335633052169411510262039);
		FCWeight4.write(33,158579480001033796370912);
		FCWeight4.write(34,479543586654150962417044);
		FCWeight4.write(35,312339736074882152405119);
		FCWeight4.write(36,1325031650906545989254813);
		FCWeight4.write(37,1181253763935486121417162);
		FCWeight4.write(38,1658365447683130699167239);
		FCWeight4.write(39,183399276427843557918665);
		FCWeight4.write(40,2177302859711293821648803);
		FCWeight4.write(41,890237902622926683255981);
		FCWeight4.write(42,2109510137641446522868741);
		FCWeight4.write(43,2194955477044554707346495);
		FCWeight4.write(44,2050313903177397794311927);
		FCWeight4.write(45,2056213125884490074626143);
		FCWeight4.write(46,2045547928278803590785937);
		FCWeight4.write(47,1836492518499640850707330);
		FCWeight4.write(48,817699457335383939662640);
		FCWeight4.write(49,1131614134391690196280984);
		FCWeight4.write(50,1058405453699537424789706);
		FCWeight4.write(51,1476884900434620004248064);
		FCWeight4.write(52,36906792751992664360352);
		FCWeight4.write(53,1447059372168336791925317);
		FCWeight4.write(54,2354678259722958561761435);
		FCWeight4.write(55,837599355824613695549630);
		FCWeight4.write(56,686671928021849380436027);
		FCWeight4.write(57,2213355803409586370032033);
		FCWeight4.write(58,1777540454895448003577820);
		FCWeight4.write(59,1855342232752827404889800);
		FCWeight4.write(60,1781608090061991930226773);
		FCWeight4.write(61,1899569290920311951782807);
		FCWeight4.write(62,2070255319266068696285337);
		FCWeight4.write(63,2090503159067768065968280);
			
		FCWeight1.read(temp_weight,0);
		CXNOR(temp_weight,hdr.fcr.ConvRes1);					//xnor-popcount for each response value
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,1);
		CXNOR(temp_weight,hdr.fcr.ConvRes2);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,2);
		CXNOR(temp_weight,hdr.fcr.ConvRes3);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,3);
		CXNOR(temp_weight,hdr.fcr.ConvRes4);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,4);
		CXNOR(temp_weight,hdr.fcr.ConvRes5);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,5);
		CXNOR(temp_weight,hdr.fcr.ConvRes6);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,6);
		CXNOR(temp_weight,hdr.fcr.ConvRes7);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,7);
		CXNOR(temp_weight,hdr.fcr.ConvRes8);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,8);
		CXNOR(temp_weight,hdr.fcr.ConvRes9);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,9);
		CXNOR(temp_weight,hdr.fcr.ConvRes10);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,10);
		CXNOR(temp_weight,hdr.fcr.ConvRes11);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,11);
		CXNOR(temp_weight,hdr.fcr.ConvRes12);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,12);
		CXNOR(temp_weight,hdr.fcr.ConvRes13);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,13);
		CXNOR(temp_weight,hdr.fcr.ConvRes14);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,14);
		CXNOR(temp_weight,hdr.fcr.ConvRes15);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,15);
		CXNOR(temp_weight,hdr.fcr.ConvRes16);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,16);
		CXNOR(temp_weight,hdr.fcr.ConvRes17);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,17);
		CXNOR(temp_weight,hdr.fcr.ConvRes18);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,18);
		CXNOR(temp_weight,hdr.fcr.ConvRes19);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,19);
		CXNOR(temp_weight,hdr.fcr.ConvRes20);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,20);
		CXNOR(temp_weight,hdr.fcr.ConvRes21);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,21);
		CXNOR(temp_weight,hdr.fcr.ConvRes22);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,22);
		CXNOR(temp_weight,hdr.fcr.ConvRes23);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,23);
		CXNOR(temp_weight,hdr.fcr.ConvRes24);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,24);
		CXNOR(temp_weight,hdr.fcr.ConvRes25);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,25);
		CXNOR(temp_weight,hdr.fcr.ConvRes26);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,26);
		CXNOR(temp_weight,hdr.fcr.ConvRes27);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,27);
		CXNOR(temp_weight,hdr.fcr.ConvRes28);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,28);
		CXNOR(temp_weight,hdr.fcr.ConvRes29);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,29);
		CXNOR(temp_weight,hdr.fcr.ConvRes30);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,30);
		CXNOR(temp_weight,hdr.fcr.ConvRes31);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,31);
		CXNOR(temp_weight,hdr.fcr.ConvRes32);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,32);
		CXNOR(temp_weight,hdr.fcr.ConvRes33);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,33);
		CXNOR(temp_weight,hdr.fcr.ConvRes34);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,34);
		CXNOR(temp_weight,hdr.fcr.ConvRes35);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,35);
		CXNOR(temp_weight,hdr.fcr.ConvRes36);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,36);
		CXNOR(temp_weight,hdr.fcr.ConvRes37);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,37);
		CXNOR(temp_weight,hdr.fcr.ConvRes38);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,38);
		CXNOR(temp_weight,hdr.fcr.ConvRes39);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,39);
		CXNOR(temp_weight,hdr.fcr.ConvRes40);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,40);
		CXNOR(temp_weight,hdr.fcr.ConvRes41);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,41);
		CXNOR(temp_weight,hdr.fcr.ConvRes42);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,42);
		CXNOR(temp_weight,hdr.fcr.ConvRes43);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,43);
		CXNOR(temp_weight,hdr.fcr.ConvRes44);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,44);
		CXNOR(temp_weight,hdr.fcr.ConvRes45);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,45);
		CXNOR(temp_weight,hdr.fcr.ConvRes46);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,46);
		CXNOR(temp_weight,hdr.fcr.ConvRes47);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,47);
		CXNOR(temp_weight,hdr.fcr.ConvRes48);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,48);
		CXNOR(temp_weight,hdr.fcr.ConvRes49);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,49);
		CXNOR(temp_weight,hdr.fcr.ConvRes50);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,50);
		CXNOR(temp_weight,hdr.fcr.ConvRes51);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,51);
		CXNOR(temp_weight,hdr.fcr.ConvRes52);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,52);
		CXNOR(temp_weight,hdr.fcr.ConvRes53);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,53);
		CXNOR(temp_weight,hdr.fcr.ConvRes54);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,54);
		CXNOR(temp_weight,hdr.fcr.ConvRes55);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,55);
		CXNOR(temp_weight,hdr.fcr.ConvRes56);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,56);
		CXNOR(temp_weight,hdr.fcr.ConvRes57);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,57);
		CXNOR(temp_weight,hdr.fcr.ConvRes58);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,58);
		CXNOR(temp_weight,hdr.fcr.ConvRes59);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,59);
		CXNOR(temp_weight,hdr.fcr.ConvRes60);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,60);
		CXNOR(temp_weight,hdr.fcr.ConvRes61);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,61);
		CXNOR(temp_weight,hdr.fcr.ConvRes62);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,62);
		CXNOR(temp_weight,hdr.fcr.ConvRes63);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight1.read(temp_weight,63);
		CXNOR(temp_weight,hdr.fcr.ConvRes64);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		temp_f1=temp_result;
		
		FCWeight2.read(temp_weight,0);
		CXNOR(temp_weight,hdr.fcr.ConvRes1);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,1);
		CXNOR(temp_weight,hdr.fcr.ConvRes2);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,2);
		CXNOR(temp_weight,hdr.fcr.ConvRes3);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,3);
		CXNOR(temp_weight,hdr.fcr.ConvRes4);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,4);
		CXNOR(temp_weight,hdr.fcr.ConvRes5);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,5);
		CXNOR(temp_weight,hdr.fcr.ConvRes6);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,6);
		CXNOR(temp_weight,hdr.fcr.ConvRes7);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,7);
		CXNOR(temp_weight,hdr.fcr.ConvRes8);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,8);
		CXNOR(temp_weight,hdr.fcr.ConvRes9);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,9);
		CXNOR(temp_weight,hdr.fcr.ConvRes10);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,10);
		CXNOR(temp_weight,hdr.fcr.ConvRes11);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,11);
		CXNOR(temp_weight,hdr.fcr.ConvRes12);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,12);
		CXNOR(temp_weight,hdr.fcr.ConvRes13);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,13);
		CXNOR(temp_weight,hdr.fcr.ConvRes14);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,14);
		CXNOR(temp_weight,hdr.fcr.ConvRes15);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,15);
		CXNOR(temp_weight,hdr.fcr.ConvRes16);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,16);
		CXNOR(temp_weight,hdr.fcr.ConvRes17);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,17);
		CXNOR(temp_weight,hdr.fcr.ConvRes18);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,18);
		CXNOR(temp_weight,hdr.fcr.ConvRes19);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,19);
		CXNOR(temp_weight,hdr.fcr.ConvRes20);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,20);
		CXNOR(temp_weight,hdr.fcr.ConvRes21);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,21);
		CXNOR(temp_weight,hdr.fcr.ConvRes22);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,22);
		CXNOR(temp_weight,hdr.fcr.ConvRes23);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,23);
		CXNOR(temp_weight,hdr.fcr.ConvRes24);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,24);
		CXNOR(temp_weight,hdr.fcr.ConvRes25);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,25);
		CXNOR(temp_weight,hdr.fcr.ConvRes26);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,26);
		CXNOR(temp_weight,hdr.fcr.ConvRes27);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,27);
		CXNOR(temp_weight,hdr.fcr.ConvRes28);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,28);
		CXNOR(temp_weight,hdr.fcr.ConvRes29);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,29);
		CXNOR(temp_weight,hdr.fcr.ConvRes30);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,30);
		CXNOR(temp_weight,hdr.fcr.ConvRes31);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,31);
		CXNOR(temp_weight,hdr.fcr.ConvRes32);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,32);
		CXNOR(temp_weight,hdr.fcr.ConvRes33);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,33);
		CXNOR(temp_weight,hdr.fcr.ConvRes34);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,34);
		CXNOR(temp_weight,hdr.fcr.ConvRes35);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,35);
		CXNOR(temp_weight,hdr.fcr.ConvRes36);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,36);
		CXNOR(temp_weight,hdr.fcr.ConvRes37);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,37);
		CXNOR(temp_weight,hdr.fcr.ConvRes38);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,38);
		CXNOR(temp_weight,hdr.fcr.ConvRes39);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,39);
		CXNOR(temp_weight,hdr.fcr.ConvRes40);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,40);
		CXNOR(temp_weight,hdr.fcr.ConvRes41);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,41);
		CXNOR(temp_weight,hdr.fcr.ConvRes42);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,42);
		CXNOR(temp_weight,hdr.fcr.ConvRes43);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,43);
		CXNOR(temp_weight,hdr.fcr.ConvRes44);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,44);
		CXNOR(temp_weight,hdr.fcr.ConvRes45);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,45);
		CXNOR(temp_weight,hdr.fcr.ConvRes46);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,46);
		CXNOR(temp_weight,hdr.fcr.ConvRes47);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,47);
		CXNOR(temp_weight,hdr.fcr.ConvRes48);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,48);
		CXNOR(temp_weight,hdr.fcr.ConvRes49);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,49);
		CXNOR(temp_weight,hdr.fcr.ConvRes50);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,50);
		CXNOR(temp_weight,hdr.fcr.ConvRes51);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,51);
		CXNOR(temp_weight,hdr.fcr.ConvRes52);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,52);
		CXNOR(temp_weight,hdr.fcr.ConvRes53);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,53);
		CXNOR(temp_weight,hdr.fcr.ConvRes54);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,54);
		CXNOR(temp_weight,hdr.fcr.ConvRes55);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,55);
		CXNOR(temp_weight,hdr.fcr.ConvRes56);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,56);
		CXNOR(temp_weight,hdr.fcr.ConvRes57);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,57);
		CXNOR(temp_weight,hdr.fcr.ConvRes58);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,58);
		CXNOR(temp_weight,hdr.fcr.ConvRes59);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,59);
		CXNOR(temp_weight,hdr.fcr.ConvRes60);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,60);
		CXNOR(temp_weight,hdr.fcr.ConvRes61);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,61);
		CXNOR(temp_weight,hdr.fcr.ConvRes62);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,62);
		CXNOR(temp_weight,hdr.fcr.ConvRes63);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight2.read(temp_weight,63);
		CXNOR(temp_weight,hdr.fcr.ConvRes64);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		temp_f2=temp_result;
		
		FCWeight3.read(temp_weight,0);
		CXNOR(temp_weight,hdr.fcr.ConvRes1);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,1);
		CXNOR(temp_weight,hdr.fcr.ConvRes2);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,2);
		CXNOR(temp_weight,hdr.fcr.ConvRes3);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,3);
		CXNOR(temp_weight,hdr.fcr.ConvRes4);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,4);
		CXNOR(temp_weight,hdr.fcr.ConvRes5);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,5);
		CXNOR(temp_weight,hdr.fcr.ConvRes6);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,6);
		CXNOR(temp_weight,hdr.fcr.ConvRes7);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,7);
		CXNOR(temp_weight,hdr.fcr.ConvRes8);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,8);
		CXNOR(temp_weight,hdr.fcr.ConvRes9);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,9);
		CXNOR(temp_weight,hdr.fcr.ConvRes10);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,10);
		CXNOR(temp_weight,hdr.fcr.ConvRes11);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,11);
		CXNOR(temp_weight,hdr.fcr.ConvRes12);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,12);
		CXNOR(temp_weight,hdr.fcr.ConvRes13);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,13);
		CXNOR(temp_weight,hdr.fcr.ConvRes14);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,14);
		CXNOR(temp_weight,hdr.fcr.ConvRes15);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,15);
		CXNOR(temp_weight,hdr.fcr.ConvRes16);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,16);
		CXNOR(temp_weight,hdr.fcr.ConvRes17);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,17);
		CXNOR(temp_weight,hdr.fcr.ConvRes18);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,18);
		CXNOR(temp_weight,hdr.fcr.ConvRes19);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,19);
		CXNOR(temp_weight,hdr.fcr.ConvRes20);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,20);
		CXNOR(temp_weight,hdr.fcr.ConvRes21);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,21);
		CXNOR(temp_weight,hdr.fcr.ConvRes22);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,22);
		CXNOR(temp_weight,hdr.fcr.ConvRes23);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,23);
		CXNOR(temp_weight,hdr.fcr.ConvRes24);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,24);
		CXNOR(temp_weight,hdr.fcr.ConvRes25);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,25);
		CXNOR(temp_weight,hdr.fcr.ConvRes26);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,26);
		CXNOR(temp_weight,hdr.fcr.ConvRes27);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,27);
		CXNOR(temp_weight,hdr.fcr.ConvRes28);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,28);
		CXNOR(temp_weight,hdr.fcr.ConvRes29);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,29);
		CXNOR(temp_weight,hdr.fcr.ConvRes30);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,30);
		CXNOR(temp_weight,hdr.fcr.ConvRes31);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,31);
		CXNOR(temp_weight,hdr.fcr.ConvRes32);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,32);
		CXNOR(temp_weight,hdr.fcr.ConvRes33);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,33);
		CXNOR(temp_weight,hdr.fcr.ConvRes34);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,34);
		CXNOR(temp_weight,hdr.fcr.ConvRes35);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,35);
		CXNOR(temp_weight,hdr.fcr.ConvRes36);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,36);
		CXNOR(temp_weight,hdr.fcr.ConvRes37);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,37);
		CXNOR(temp_weight,hdr.fcr.ConvRes38);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,38);
		CXNOR(temp_weight,hdr.fcr.ConvRes39);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,39);
		CXNOR(temp_weight,hdr.fcr.ConvRes40);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,40);
		CXNOR(temp_weight,hdr.fcr.ConvRes41);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,41);
		CXNOR(temp_weight,hdr.fcr.ConvRes42);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,42);
		CXNOR(temp_weight,hdr.fcr.ConvRes43);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,43);
		CXNOR(temp_weight,hdr.fcr.ConvRes44);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,44);
		CXNOR(temp_weight,hdr.fcr.ConvRes45);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,45);
		CXNOR(temp_weight,hdr.fcr.ConvRes46);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,46);
		CXNOR(temp_weight,hdr.fcr.ConvRes47);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,47);
		CXNOR(temp_weight,hdr.fcr.ConvRes48);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,48);
		CXNOR(temp_weight,hdr.fcr.ConvRes49);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,49);
		CXNOR(temp_weight,hdr.fcr.ConvRes50);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,50);
		CXNOR(temp_weight,hdr.fcr.ConvRes51);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,51);
		CXNOR(temp_weight,hdr.fcr.ConvRes52);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,52);
		CXNOR(temp_weight,hdr.fcr.ConvRes53);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,53);
		CXNOR(temp_weight,hdr.fcr.ConvRes54);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,54);
		CXNOR(temp_weight,hdr.fcr.ConvRes55);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,55);
		CXNOR(temp_weight,hdr.fcr.ConvRes56);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,56);
		CXNOR(temp_weight,hdr.fcr.ConvRes57);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,57);
		CXNOR(temp_weight,hdr.fcr.ConvRes58);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,58);
		CXNOR(temp_weight,hdr.fcr.ConvRes59);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,59);
		CXNOR(temp_weight,hdr.fcr.ConvRes60);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,60);
		CXNOR(temp_weight,hdr.fcr.ConvRes61);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,61);
		CXNOR(temp_weight,hdr.fcr.ConvRes62);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,62);
		CXNOR(temp_weight,hdr.fcr.ConvRes63);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight3.read(temp_weight,63);
		CXNOR(temp_weight,hdr.fcr.ConvRes64);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		temp_f3=temp_result;
		
		FCWeight4.read(temp_weight,0);
		CXNOR(temp_weight,hdr.fcr.ConvRes1);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,1);
		CXNOR(temp_weight,hdr.fcr.ConvRes2);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,2);
		CXNOR(temp_weight,hdr.fcr.ConvRes3);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,3);
		CXNOR(temp_weight,hdr.fcr.ConvRes4);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,4);
		CXNOR(temp_weight,hdr.fcr.ConvRes5);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,5);
		CXNOR(temp_weight,hdr.fcr.ConvRes6);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,6);
		CXNOR(temp_weight,hdr.fcr.ConvRes7);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,7);
		CXNOR(temp_weight,hdr.fcr.ConvRes8);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,8);
		CXNOR(temp_weight,hdr.fcr.ConvRes9);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,9);
		CXNOR(temp_weight,hdr.fcr.ConvRes10);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,10);
		CXNOR(temp_weight,hdr.fcr.ConvRes11);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,11);
		CXNOR(temp_weight,hdr.fcr.ConvRes12);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,12);
		CXNOR(temp_weight,hdr.fcr.ConvRes13);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,13);
		CXNOR(temp_weight,hdr.fcr.ConvRes14);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,14);
		CXNOR(temp_weight,hdr.fcr.ConvRes15);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,15);
		CXNOR(temp_weight,hdr.fcr.ConvRes16);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,16);
		CXNOR(temp_weight,hdr.fcr.ConvRes17);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,17);
		CXNOR(temp_weight,hdr.fcr.ConvRes18);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,18);
		CXNOR(temp_weight,hdr.fcr.ConvRes19);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,19);
		CXNOR(temp_weight,hdr.fcr.ConvRes20);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,20);
		CXNOR(temp_weight,hdr.fcr.ConvRes21);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,21);
		CXNOR(temp_weight,hdr.fcr.ConvRes22);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,22);
		CXNOR(temp_weight,hdr.fcr.ConvRes23);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,23);
		CXNOR(temp_weight,hdr.fcr.ConvRes24);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,24);
		CXNOR(temp_weight,hdr.fcr.ConvRes25);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,25);
		CXNOR(temp_weight,hdr.fcr.ConvRes26);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,26);
		CXNOR(temp_weight,hdr.fcr.ConvRes27);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,27);
		CXNOR(temp_weight,hdr.fcr.ConvRes28);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,28);
		CXNOR(temp_weight,hdr.fcr.ConvRes29);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,29);
		CXNOR(temp_weight,hdr.fcr.ConvRes30);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,30);
		CXNOR(temp_weight,hdr.fcr.ConvRes31);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,31);
		CXNOR(temp_weight,hdr.fcr.ConvRes32);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,32);
		CXNOR(temp_weight,hdr.fcr.ConvRes33);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,33);
		CXNOR(temp_weight,hdr.fcr.ConvRes34);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,34);
		CXNOR(temp_weight,hdr.fcr.ConvRes35);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,35);
		CXNOR(temp_weight,hdr.fcr.ConvRes36);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,36);
		CXNOR(temp_weight,hdr.fcr.ConvRes37);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,37);
		CXNOR(temp_weight,hdr.fcr.ConvRes38);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,38);
		CXNOR(temp_weight,hdr.fcr.ConvRes39);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,39);
		CXNOR(temp_weight,hdr.fcr.ConvRes40);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,40);
		CXNOR(temp_weight,hdr.fcr.ConvRes41);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,41);
		CXNOR(temp_weight,hdr.fcr.ConvRes42);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,42);
		CXNOR(temp_weight,hdr.fcr.ConvRes43);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,43);
		CXNOR(temp_weight,hdr.fcr.ConvRes44);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,44);
		CXNOR(temp_weight,hdr.fcr.ConvRes45);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,45);
		CXNOR(temp_weight,hdr.fcr.ConvRes46);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,46);
		CXNOR(temp_weight,hdr.fcr.ConvRes47);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,47);
		CXNOR(temp_weight,hdr.fcr.ConvRes48);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,48);
		CXNOR(temp_weight,hdr.fcr.ConvRes49);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,49);
		CXNOR(temp_weight,hdr.fcr.ConvRes50);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,50);
		CXNOR(temp_weight,hdr.fcr.ConvRes51);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,51);
		CXNOR(temp_weight,hdr.fcr.ConvRes52);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,52);
		CXNOR(temp_weight,hdr.fcr.ConvRes53);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,53);
		CXNOR(temp_weight,hdr.fcr.ConvRes54);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,54);
		CXNOR(temp_weight,hdr.fcr.ConvRes55);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,55);
		CXNOR(temp_weight,hdr.fcr.ConvRes56);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,56);
		CXNOR(temp_weight,hdr.fcr.ConvRes57);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,57);
		CXNOR(temp_weight,hdr.fcr.ConvRes58);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,58);
		CXNOR(temp_weight,hdr.fcr.ConvRes59);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,59);
		CXNOR(temp_weight,hdr.fcr.ConvRes60);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,60);
		CXNOR(temp_weight,hdr.fcr.ConvRes61);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,61);
		CXNOR(temp_weight,hdr.fcr.ConvRes62);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,62);
		CXNOR(temp_weight,hdr.fcr.ConvRes63);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		FCWeight4.read(temp_weight,63);
		CXNOR(temp_weight,hdr.fcr.ConvRes64);
		CBitCount(CXNOROutput);
		temp_result=temp_result<<1;
		temp_result=temp_result+(bit<64>)CResponse;
		temp_f4=temp_result;

		BBitCount(temp_f1);
		final_f1=BResponse;
		
		BBitCount(temp_f2);
		final_f2=BResponse;					//collate FC layer responses
		
		BBitCount(temp_f3);
		final_f3=BResponse;
		
		BBitCount(temp_f4);
		final_f4=BResponse;
		
		bit<4> FCFinal=final_f1++final_f2++final_f3++final_f4;
		
		bit<4> temp_OWeight=0;				//output layer calculation
		bit<4> Out1=0;
		bit<4> Out2=0;
		OWeight1.read(temp_OWeight,0);
		OXNOR(temp_OWeight,FCFinal);
		Out1=OXNOROutput;
		
		OWeight2.read(temp_OWeight,0);
		OXNOR(temp_OWeight,FCFinal);
		Out2=OXNOROutput;
		
		if (Out1 > Out2) {					//class decision
			final_class=0;
		}			
		else {
			final_class=1;
		}
        
		

	    standard_metadata.egress_spec=6;  

    
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

