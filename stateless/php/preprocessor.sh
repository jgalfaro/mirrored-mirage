#! /bin/bash
#
# Copyright (C) 2005, 2006 seres@ents-bretagne.fr
#

prename=`echo $1 | cut -d / -f 2`
name=`echo $prename | cut -d . -f 1`

NetModelTag=`grep -n "<net_model>" $1 | head -n 1| cut -d : -f 1`
EndNetModelTag=`grep -n "</net_model>" $1 | tail -n 1| cut -d : -f 1`


filename=`echo "pre/$name""_pre.xml"`


#---------------------- XML and NetModel Headers --------------------------------------------
#XML header
head -n 2 $1 > $filename
#net_model header
head -n $NetModelTag $1 | tail -n 1 >> $filename
#---------------------- XML and NetModel Headers --------------------------------------------


#----------------------NETWORKS--------------------------------------------------------------
firstTag=`grep -n "<network>" $1 | head -n 1| cut -d : -f 1`
lastTag=`grep -n "</network>" $1 | tail -n 1| cut -d : -f 1`
if [ "$firstTag" != "" ]; then
 diff=`echo $lastTag - $firstTag + 1| bc`
 head -n $lastTag $1 | tail -n $diff >> $filename
fi
#----------------------NETWORKS--------------------------------------------------------------


#-----------------------HOSTS----------------------------------------------------------------
firstTag=`grep -n "<host>" $1 | head -n 1| cut -d : -f 1`
lastTag=`grep -n "</host>" $1 | tail -n 1| cut -d : -f 1`
if [ "$firstTag" != "" ]; then
 diff=`echo $lastTag - $firstTag + 1| bc`
 head -n $lastTag $1 | tail -n $diff >> $filename
fi
#-----------------------HOSTS----------------------------------------------------------------


#----------------------NETWORK_INTERFACES----------------------------------------------------
firstTag=`grep -n "<net_interface>" $1 | head -n 1| cut -d : -f 1`
lastTag=`grep -n "</net_interface>" $1 | tail -n 1| cut -d : -f 1`
if [ "$firstTag" != "" ]; then
 diff=`echo $lastTag - $firstTag + 1| bc`
 head -n $lastTag $1 | tail -n $diff >> $filename
fi
#----------------------NETWORK_INTERFACES----------------------------------------------------


#---------------------SERVICES---------------------------------------------------------------
#firstTag=`grep -n "<service>" $1 | head -n 1| cut -d : -f 1`
#lastTag=`grep -n "</service>" $1 | tail -n 1| cut -d : -f 1`
#diff=`echo $lastTag - $firstTag +1 | bc`
#head -n $lastTag $1 | tail -n $diff >> $filename
#---------------------SERVICES---------------------------------------------------------------


#-----------------------HOST_GROUPS----------------------------------------------------------
#firstTag=`grep -n "<host_group>" $1 | head -n 1| cut -d : -f 1`
#lastTag=`grep -n "</host_group>" $1 | tail -n 1| cut -d : -f 1`
#diff=`echo $lastTag - $firstTag + 1| bc`
#head -n $lastTag $1 | tail -n $diff >> $filename
#-----------------------HOST_GROUPS----------------------------------------------------------


#--------------------VULNERABILITIES---------------------------------------------------------
#firstTag=`grep -n "<vulnerability>" $1 | head -n 1| cut -d : -f 1`
#lastTag=`grep -n "</vulnerability>" $1 | tail -n 1| cut -d : -f 1`
#diff=`echo $lastTag - $firstTag +1 | bc`
#head -n $lastTag $1 | tail -n $diff >> $filename
#--------------------VULNERABILITIES---------------------------------------------------------


#--------------------TICKETS----------------------------------------------------------------
firstTag=`grep -n "<ticket>" $1 | head -n 1| cut -d : -f 1`
lastTag=`grep -n "</ticket>" $1 | tail -n 1| cut -d : -f 1`
if [ "$firstTag" != "" ]; then
 diff=`echo $lastTag - $firstTag +1 | bc`
 head -n $lastTag $1 | tail -n $diff >> $filename
fi
#--------------------TICKETS----------------------------------------------------------------


#--------------------ROUTING_RULES------------------------------------------------------------
#firstTag=`grep -n "<routing_rule>" $1 | head -n 1| cut -d : -f 1`
#lastTag=`grep -n "</routing_rule>" $1 | tail -n 1| cut -d : -f 1`
#diff=`echo $lastTag - $firstTag +1 | bc`
#head -n $lastTag $1 | tail -n $diff >> $filename
#--------------------ROUTING_RULES------------------------------------------------------------


#--------------------ACCESS_RULES------------------------------------------------------------
firstTag=`grep -n "<access_rule>" $1 | head -n 1| cut -d : -f 1`
lastTag=`grep -n "</access_rule>" $1 | tail -n 1| cut -d : -f 1`
if [ "$firstTag" != "" ]; then
 diff=`echo $lastTag - $firstTag +1 | bc`
 head -n $lastTag $1 | tail -n $diff >> $filename
fi
#--------------------ACCESS_RULES------------------------------------------------------------


#---------------------- NetModel and XML tail -----------------------------------------------
#net_model bottom
head -n $EndNetModelTag $1 | tail -n 1 >> $filename
#XML bottom
tail -n 1 $1 >> $filename
#---------------------- NetModel and XML tail -----------------------------------------------


#---------------- Excluding some labels -----------------------------------------------------
a="cat $filename"

for i in `grep -v '#' exclude-labels.d/network`;do a="$a | grep -v \"$i\"";done
for i in `grep -v '#' exclude-labels.d/host`;do a="$a | grep -v \"$i\"";done
for i in `grep -v '#' exclude-labels.d/net_interface`;do a="$a | grep -v \"$i\"";done
for i in `grep -v '#' exclude-labels.d/ticket`;do a="$a | grep -v \"$i\"";done
for i in `grep -v '#' exclude-labels.d/access-rule`;do a="$a | grep -v \"$i\"";done

a="$a > $filename.tmp"

eval $a

mv $filename.tmp $filename

#---------------- Excluding some labels -----------------------------------------------------
