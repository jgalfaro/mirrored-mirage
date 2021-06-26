<?php

/*
** Copyright (C) 2005, 2006 seres@ents-bretagne.fr
*/

include("XML/Unserializer.php");
include("XML/Serializer.php");

if($generate=="view"){
  header('Content-type: text/xml');
  printf("%s",base64_decode($data));
}elseif($generate=="save"){
  header('Content-Disposition: attachment; filename="'.$outputFilename.'"');
  printf("%s",base64_decode($data));
}elseif($generate=="update"){
  if (!$handle = fopen($updateFilename, 'w')) {
    echo "Cannot open file $updateFilename";
    exit;
  }
  if (fwrite($handle, base64_decode($data)) === FALSE) {
    echo "Cannot write to file $updateFilename";
    exit;
  }
  fclose($handle);
  header("Location: ./gui.php");
}elseif(($generate=="netfilter")or($generate=="saveNetfilter")){

  if($generate=="netfilter"){
    header('Content-type: text/plain');
  }elseif($generate=="saveNetfilter"){
    header('Content-Disposition: attachment; filename="'.$outputFilename.'"');
  }

  $options = array('parseAttributes'=>true);
  $unserializer = &new XML_Unserializer($options);
  $result = $unserializer->unserialize(base64_decode($data));
  $data = $unserializer->getUnserializedData();

  foreach($data[components][fw] as $fw){

    if($fw[name]==$component){

      $script=sprintf("#! /bin/bash\n");
      $script=sprintf("%s%s",$script,"iptables -t filter -F\n");
      $script=sprintf("%s%s",$script,"iptables -t filter -X\n");
      $script=sprintf("%s%s",$script,"\n");
      if($fw[policy]=="open"){
        $script=sprintf("%s%s",$script,"iptables -P FORWARD ACCEPT\n");
      }elseif($fw[policy]=="close"){
        $script=sprintf("%s%s",$script,"iptables -P FORWARD DROP\n");
      }
      //$script=sprintf("%s%s",$script,"iptables -P INPUT DROP\n");
      //$script=sprintf("%s%s",$script,"iptables -P OUTPUT DROP\n");
      $script=sprintf("%s%s",$script,"\n");

      $nrules=1;
      foreach($fw[rule] as $rule){
        $script=sprintf("%s#R%d\n",$script,$nrules);
        $nrules++;

        //source
        $s=explode(",",$rule[condition][subcondition][0][s]);
        unset($source);
        $ns=0;
        $source[$ns]=range2cidr($s[0],$s[1]);
        $min=$s[0];
        $max=$s[1];
        while($source[$ns]==NULL){
          $maxMask=0;
          do{
            $max=long2ip(ip2long($max)-1);
            $source[$ns]=range2cidr($min,$max);
            $maxMask++;
          }while(($source[$ns]==NULL)and($maxMask<(255*8)));
          $min=long2ip(ip2long($max)+1);
          $max=$s[1];
          if($maxMask>=(255*8)){
            $source[$ns]="-1";
          }else{
            $ns++;
            $source[$ns]=range2cidr($min,$max);
          }
        }

        //destination
        $d=explode(",",$rule[condition][subcondition][0][d]);
        unset($dest);
        $nd=0;
        $dest[$nd]=range2cidr($d[0],$d[1]);
        $min=$d[0];
        $max=$d[1];
        while(($dest[$nd]==NULL)){
          $maxMask=0;
          do{
            $max=long2ip(ip2long($max)-1);
            $dest[$nd]=range2cidr($min,$max);
            $maxMask++;
          }while(($dest[$nd]==NULL)and($maxMask<(255*8)));
          $min=long2ip(ip2long($max)+1);
          $max=$d[1];
          if($maxMask>=(255*8)){
            $dest[$nd]="-1";
          }else{
            $nd++;
            $dest[$nd]=range2cidr($min,$max);
          }

        }

        //source-port
        $sP=explode(",",$rule[condition][subcondition][0][sP]);
        if($sP[0]==$sP[1]){
          $sport=sprintf("--sport %s",$sP[0]);
        }else{
          $sport=sprintf("--sport %s:%s",$sP[0],$sP[1]);
        }

        //destination-port
        $dP=explode(",",$rule[condition][subcondition][0][dP]);
        if($dP[0]==$dP[1]){
          $dport=sprintf("--dport %s",$dP[0]);
        }else{
          $dport=sprintf("--dport %s:%s",$dP[0],$dP[1]);
        }


        //protocol
        if($rule[condition][subcondition][0][p]=="1,1"){
          $protocol=sprintf("-p tcp %s %s",$sport,$dport);
        }elseif($rule[condition][subcondition][0][p]=="2,2"){
          $protocol=sprintf("-p udp %s %s",$sport,$dport);
        }elseif($rule[condition][subcondition][0][p]=="1,2"){
          $protocol="-p all";
        }elseif($rule[condition][subcondition][0][p]=="3,3"){
          $protocol="-p icmp";
        }

        //decision
        if($rule[decision]=="accept"){
          $decision="-j ACCEPT\n";
        }elseif($rule[decision]=="deny"){
          $decision="-j DROP\n";
        }


        foreach($source as $src){
          foreach($dest as $dst){
            if(($src==-1)and($dst==-1)){
              $script=sprintf("%s#Warning! both source and destination address are out of range ... \n",$script);
              $script=sprintf("%s#You should manually modify this entry!\n",$script);
              $script=sprintf("%s%s %s %s %s %s %s",$script,"#iptables -A FORWARD -s",$rule[condition][subcondition][0][s],"-d",$rule[condition][subcondition][0][d],$protocol,$decision);
            }elseif($src==-1){
              $script=sprintf("%s#Warning! source address %s is out of range ... \n",$script,$rule[condition][subcondition][0][s]);
              $script=sprintf("%s#You should manually modify this entry!\n",$script);
              $script=sprintf("%s%s %s %s %s %s %s",$script,"#iptables -A FORWARD -s",$rule[condition][subcondition][0][s],"-d",$dst,$protocol,$decision);
            }elseif($dst==-1){
              $script=sprintf("%s#Warning! destination address %s is out of range ... \n",$script,$rule[condition][subcondition][0][d]);
              $script=sprintf("%s#You should manually modify this entry!\n",$script);
              $script=sprintf("%s%s %s %s %s %s %s",$script,"#iptables -A FORWARD -s",$src,"-d",$rule[condition][subcondition][0][d],$protocol,$decision);
            }else{
              $script=sprintf("%s%s %s %s %s %s %s",$script,"iptables -A FORWARD -s",$src,"-d",$dst,$protocol,$decision);
            }
          }
        }
        $script=sprintf("%s%s",$script,"\n");


      }
      echo "$script";
      //print_r($data);
    }
  }
}elseif(($generate=="snort")or($generate=="saveSnort")){

  if($generate=="snort"){
    header('Content-type: text/plain');
  }elseif($generate=="saveSnort"){
    header('Content-Disposition: attachment; filename="'.$outputFilename.'"');
  }

  $options = array('parseAttributes'=>true);
  $unserializer = &new XML_Unserializer($options);
  $result = $unserializer->unserialize(base64_decode($data));
  $data = $unserializer->getUnserializedData();

  foreach($data[components][fw] as $fw){

    if($fw[name]==$component){

      $script=sprintf("");

      $script=sprintf("%s%s",$script,"\n");

      $nrules=1;
      foreach($fw[rule] as $rule){
        $script=sprintf("%s#R%d\n",$script,$nrules);
        $nrules++;

        //source
        $s=explode(",",$rule[condition][subcondition][0][s]);
        unset($source);
        $ns=0;
        $source[$ns]=range2cidr($s[0],$s[1]);
        $min=$s[0];
        $max=$s[1];
        while($source[$ns]==NULL){
          $maxMask=0;
          do{
            $max=long2ip(ip2long($max)-1);
            $source[$ns]=range2cidr($min,$max);
            $maxMask++;
          }while(($source[$ns]==NULL)and($maxMask<(255*8)));
          $min=long2ip(ip2long($max)+1);
          $max=$s[1];
          if($maxMask>=(255*8)){
            $source[$ns]="-1";
          }else{
            $ns++;
            $source[$ns]=range2cidr($min,$max);
          }
        }

        //destination
        $d=explode(",",$rule[condition][subcondition][0][d]);
        unset($dest);
        $nd=0;
        $dest[$nd]=range2cidr($d[0],$d[1]);
        $min=$d[0];
        $max=$d[1];
        while(($dest[$nd]==NULL)){
          $maxMask=0;
          do{
            $max=long2ip(ip2long($max)-1);
            $dest[$nd]=range2cidr($min,$max);
            $maxMask++;
          }while(($dest[$nd]==NULL)and($maxMask<(255*8)));
          $min=long2ip(ip2long($max)+1);
          $max=$d[1];
          if($maxMask>=(255*8)){
            $dest[$nd]="-1";
          }else{
            $nd++;
            $dest[$nd]=range2cidr($min,$max);
          }

        }

        //source-port
        $sP=explode(",",$rule[condition][subcondition][0][sP]);
        if($sP[0]==$sP[1]){
          $sport=sprintf("%s",$sP[0]);
        }elseif(($sP[0]=="1") and ($sP[1]=="65535")){
          $sport=sprintf("any");
        }else{
          $sport=sprintf("%s:%s",$sP[0],$sP[1]);
        }

        //destination-port
        $dP=explode(",",$rule[condition][subcondition][0][dP]);
        if($dP[0]==$dP[1]){
          $dport=sprintf("%s",$dP[0]);
        }elseif(($dP[0]=="1") and ($dP[1]=="65535")){
          $dport=sprintf("any");
        }else{
          $dport=sprintf("%s:%s",$dP[0],$dP[1]);
        }


        //protocol
        if($rule[condition][subcondition][0][p]=="1,1"){
          $protocol=sprintf("tcp");
        }elseif($rule[condition][subcondition][0][p]=="2,2"){
          $protocol=sprintf("udp");
        }elseif($rule[condition][subcondition][0][p]=="1,2"){
          $protocol="any";
        }elseif($rule[condition][subcondition][0][p]=="3,3"){
          $protocol="icmp";
        }

        //decision
        if($rule[decision]=="accept"){
          $decision="pass ";
        }elseif($rule[decision]=="deny"){
          $decision="alert ";
        }


        foreach($source as $src){
          foreach($dest as $dst){
            if(($src==-1)and($dst==-1)){
              $script=sprintf("%s#Warning! both source and destination address are out of range ... \n",$script);
              $script=sprintf("%s#You should manually modify this entry!\n",$script);
              $script=sprintf("%s#%s %s %s %s -> %s %s (%s)\n",$script,$decision,$protocol,$rule[condition][subcondition][0][s],$sport,$rule[condition][subcondition][0][d],$dport,$rule[nids_misc]);
            }elseif($src==-1){
              $script=sprintf("%s#Warning! source address %s is out of range ... \n",$script,$rule[condition][subcondition][0][s]);
              $script=sprintf("%s#You should manually modify this entry!\n",$script);
              $script=sprintf("%s#%s %s %s %s -> %s %s (%s)\n",$script,$decision,$protocol,$rule[condition][subcondition][0][s],$sport,$dst,$dport,$rule[nids_misc]);
            }elseif($dst==-1){
              $script=sprintf("%s#Warning! destination address %s is out of range ... \n",$script,$rule[condition][subcondition][0][d]);
              $script=sprintf("%s#You should manually modify this entry!\n",$script);
              $script=sprintf("%s#%s %s %s %s -> %s %s (%s)\n",$script,$decision,$protocol,$src,$sport,$rule[condition][subcondition][0][d],$dport,$rule[nids_misc]);
            }else{
              $script=sprintf("%s%s %s %s %s -> %s %s (%s)\n",$script,$decision,$protocol,$src,$sport,$dst,$dport,$rule[nids_misc]);
            }
          }
        }
        $script=sprintf("%s%s",$script,"\n");
      }

      if($fw[policy]=="close"){
        $script=sprintf("\n%s#Default policy ... \n",$script);
        $script=sprintf("%s%s %s %s %s -> %s %s (%s)\n",$script,"alert","any","0.0.0.0/24","any","0.0.0.0/24","any","msg:\"Alert about any traffic\"; classtype:\"non-allowed-activity\";");
      }
      echo "$script";
      //print_r($data);
    }
  }
}//else


function range2cidr($ip_start,$ip_end) {
  if((long2ip(ip2long($ip_start))!=$ip_start) or
     (long2ip(ip2long($ip_end))!=$ip_end)
    ){
    return NULL;
  }
  $ipl_start=(int)ip2long($ip_start);
  $ipl_end=(int)ip2long($ip_end);
  if($ipl_start>0 && $ipl_end<0){
    $delta=($ipl_end+4294967296)-$ipl_start;
  }
  else{
    $delta=$ipl_end-$ipl_start;
  }
  $netmask=str_pad(decbin($delta),32,"0","STR_PAD_LEFT");
  if(ip2long($ip_start)==0 && substr_count($netmask,"1")==32){
    return "0.0.0.0/0";
  }
  if($delta<0 or ($delta>0 && $delta%2==0)){
    return NULL;
  }
  for($mask=0;$mask<32;$mask++){
    if($netmask[$mask]==1){
      break;
    }
  }
  if(substr_count($netmask,"0")!=$mask){
    return NULL;
  }
  return "$ip_start/$mask";
}


?>

