# COE 557 Homework 3 - Building and Optimizing an Intelligent SDN Network with Ryu
This repository holds the source code for the 3rd lab of COE 557 - Term 252, below is a simple step-by-step guide to launch the homework lab.

## Prerequisites
Docker must be installed as the Ryu controller is containerized, please follow the guide [here](https://docs.docker.com/engine/install/).

Also, mininet is required, please install it via the following (assuming you are using Ubuntu22.04):
```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y net-tools iproute2 tcpdump wireshark-common
sudo apt install -y mininet openvswitch-switch openvswitch-common
```

Test that Mininet works properly, Mininet should create a small topology and hosts can ping each other with this command to test things out.
```bash
sudo mn --test pingall
```

Clear Mininet configs for clean spin-up later
```bash
sudo mn -c
```

## Run the lab
To run the lab, first spinup the Ryu controller container by using the given docker compose file:
```bash
sudo docker compose up -d
```

You can check the container status by running:
```bash
sudo docker ps
```

To bring the lab down, run the following:
```bash
sudo docker compose down
```

This deployment should expose port `8080` and `6653` via localhost.

Create a simple mininet network, it should be able to connect to the Ryu controller now.
```bash
sudo mn --topo single,3 \
  --controller remote,ip=127.0.0.1,port=6653 \
  --switch ovsk,protocols=OpenFlow13
```

Inside Mininet, you can run the following to test the network:
```bash
h1 ping -c 3 h3
h2 ping -c 3 h3
```

You can view the installed policies in the switch by OpenFlow (Through the Ryu controller) by running this command in a new terminal of the same host:
```bash
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```