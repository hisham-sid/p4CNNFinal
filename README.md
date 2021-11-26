# p4CNNFinal

Download the P4 Virtual Machine from: https://p4.org/events/2019-04-30-p4-developer-day/

Clone this repository from: https://github.com/hisham-sid/p4CNNFinal (use git clone [name of the repositoy])

Run the veth_setup.sh script: 
  cd p4CNNFinal
  chmod +x veth_setup.sh 
  ./veth_setup.sh
  
Open 5 terminals in the p4CNN folder
In terminal 1:
  p4c --target bmv2 --arch v1model switch1.p4 
  sudo simple_switch -i 1@veth1 -i 2@veth2 switch1.json --thrift-port 1010
  
In terminal 2:
  p4c --target bmv2 --arch v1model switch2.p4 
  sudo rm /tmp/bmv2-0-notifications.ipc
  sudo simple_switch -i 4@veth4 -i 4@veth4 switch2.json --thrift-port 2020
  
In terminal 3:
  p4c --target bmv2 --arch v1model switch3.p4
  sudo rm /tmp/bmv2-0-notifications.ipc
  sudo simple_switch -i 5@veth5 -i 6@veth6 switch3.json --thrift-port 3030
  
in terminal 4:
  sudo simple_switch_CLI > s1comm.txt --thrift-port 1010
  sudo simple_switch_CLI > s32comm.txt --thrift-port 3030
  sudo ./receive.py

in terminal 5:
  sudo ./send.py 10.0.0.2 <your-image-name>
  
