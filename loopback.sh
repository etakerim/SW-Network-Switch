# sudo su

#####CREATE###################################
ip link add name sw-port0 type dummy
ip link set sw-port0 up
ip addr add 1.1.1.1/32 dev sw-port0 

ip link add name sw-port1 type dummy
ip link set sw-port1 up
ip addr add 1.1.1.2/32 dev sw-port1
#######################################

# ping 1.1.1.1
# ip addr show sw-port1

######TEARDOWN##################################
ip addr delete 1.1.1.1/32 dev sw-port0
ip link set sw-port0 down
ip link delete name sw-port0 type dummy

ip addr delete 1.1.1.2/32 dev sw-port1
ip link set sw-port1 down
ip link delete name sw-port1 type dummy
#######################################
