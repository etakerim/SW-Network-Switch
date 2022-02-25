
ip link add name loop1 type dummy
ip link set loop1 up

sudo su
ip link add name P0 type dummy
ip link set P0 up
ip link add name P1 type dummy
ip link set P1 up

#####CREATE###################################
ip link add name P0 type dummy
ip link set P0 up
ip addr add 1.1.1.1/32 dev P0 

ip link add name P1 type dummy
ip link set P1 up
ip addr add 1.1.1.2/32 dev P1
#######################################

# ping 1.1.1.1
# ip addr show P1

######TEARDOWN##################################
ip addr delete 1.1.1.1/32 dev P0
ip link set P0 down
ip link delete name P0 type dummy

ip addr delete 1.1.1.2/32 dev P1
ip link set P1 down
ip link delete name P1 type dummy
#######################################
