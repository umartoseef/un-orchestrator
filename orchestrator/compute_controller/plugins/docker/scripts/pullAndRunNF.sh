#!/bin/bash

#Author: Ivano Cerrato
#Date: June 16th 2014
#Brief: pull a NF from a docker repository, and run it.

#command line: sudo ./pullAndRunNF.sh $1 $2 $3 $4 [$5 ...]

#$1 LSI ID				(e.g., 2)
#$2 NF name				(e.g., firewall)
#$3 registry/nf[:tag] 	(e.g., localhost:5000/pcap:latest)
#$4 number_of_ports		(e.g., 2)
#The next $4 parameters are port names to be provided to the container (e.g., vEth0 vEth1)

tmp_file="$1_$2_tmp"

if (( $EUID != 0 ))
then
    echo "[$0] This script must be executed with ROOT privileges"
    exit 0
fi

echo -ne "sudo docker run -d --name $1_$2 "   > $tmp_file

echo --net=\"none\"  --privileged=true  $3 >> $tmp_file

echo [`date`]"[$0] Executing command: '"`cat $tmp_file`"'"

ID=`bash $tmp_file`

#docker run returns 0 in case of success
ret=`echo $?`

if [ $ret -eq 0 ]
then
	echo [`date`]"[$0] Container $2 started with ID: '"$ID"'"
else
	echo "[$0] An error occurred while starting the container"
	rm $tmp_file
	exit 0
fi

#Save the binding lsi-nf-docker id on a file
file="$1_$2"
echo $ID >> $file

rm $tmp_file

#The following code configures the network for the container just created.
#It is based on the description provided at
#	http://docs.docker.com/articles/networking/#container-networking

PID=`docker inspect --format '{{ .State.Pid }}' $ID`

sudo mkdir -p /var/run/netns
sudo ln -s /proc/$PID/ns/net /var/run/netns/$PID
	
current=5

for (( c=0; c<$4; c++ ))
do	
	ip link set ${!current} netns $PID
	
	echo "[$0] Inserting port ${!current} inside a container. It will have name eth$c"
	
	ip netns exec $PID ip link set dev ${!current} name eth$c
				
 	ip netns exec $PID ip link set eth$c up
	
	current=`expr $current + 1`
done

exit 1
