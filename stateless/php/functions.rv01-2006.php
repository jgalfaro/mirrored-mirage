<?

/*
** Copyright (C) 2005, 2006 seres@ents-bretagne.fr
*/


//---------------------- Main Functions -------------------------------------------
// Based on the PHP Package XML_Serializer maintained by Stephan Schmidt and
// licensed under the terms of the PHP License, version 2.02.
// Cf.
//        http://www.php.net/license/2_02.txt
//        http://pear.php.net/user/schst


//(1)parser([...])
function parser($path,$file,$generateOutput,$savefilename){

  //$ini= memory_get_usage();
  printf("<b> Memory Limit: </b> %sb <br>",get_cfg_var("memory_limit"));
  printf("<b> CPU Time Limit: </b> %ss <br>",get_cfg_var("max_execution_time"));
  //printf("<b> Memory Allocated: </b> %u (bytes)  ~ %u (kbytes) <BR><BR>",$ini, $ini/1024);

  echo "<BR>/* Unserializing <a href=\"$path/$file\">$file</a> ....";

  $start = my_microtime();
  $options = array('parseAttributes'=>true);
  $unserializer = &new XML_Unserializer($options);
  $result = $unserializer->unserialize($path."/".$file,true);
  $data = $unserializer->getUnserializedData();

  $end = my_microtime();
  printf("... done in %f seconds! */<BR>",round($end-$start,5));
  $start2 = my_microtime();

  $xml_header="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

  $parsed=sprintf("%s",$xml_header);
  $parsed=sprintf("%s<topology>\n",$parsed);

  // ---------------------- hosts ----------------
  $i=0;
  $parsed=sprintf("%s <hosts>\n",$parsed);
  foreach($data[net_model][host] as $host){
    if($host[system_type_enum]=="Router"||$host[system_type_enum]=="Firewall"||$host[system_type_enum]=="NIDS"){
      $id=$host[id];
      $component[$id]=$host[name_from_user];
      $parsed=sprintf("%s  <host name=\"%s\" id=\"C%s\"",$parsed,$host[name_from_user],$host[id]);
      $parsed=sprintf("%s type=\"%s\"",$parsed,$host[system_type_enum]);
      $parsed=sprintf("%s IP_address=\"%s\"></host>\n",$parsed,long2ip($host[primary_ip_address]));
      if($host[system_type_enum]=="Firewall"||$host[system_type_enum]=="NIDS"){
        $firewall[$i]=$id;
        $i++;
      }
    }elseif($host[user_type_enum]=="Router"||$host[user_type_enum]=="Firewall"){
      $id=$host[id];
      $component[$id]=$host[name_from_user];
      $parsed=sprintf("%s  <host name=\"%s\" id=\"C%s\"",$parsed,$host[name_from_user],$host[id]);
      $parsed=sprintf("%s type=\"%s\"",$parsed,$host[user_type_enum]);
      $parsed=sprintf("%s IP_address=\"%s\"></host>\n",$parsed,long2ip($host[primary_ip_address]));
      if($host[user_type_enum]=="Firewall"||$host[user_type_enum]=="NIDS"){
        $firewall[$i]=$id;
        $i++;
      }
    }
  }
  $parsed=sprintf("%s </hosts>\n",$parsed);
  // ---------------------- hosts ----------------


  // ---------------------- access_rules ---------
  $parsed=sprintf("%s <rules>\n",$parsed);
  foreach($firewall as $f){
    $type="";
    foreach($data[net_model][host] as $host){
      if($host[id]==$f){
        if($host[system_type_enum]=="Firewall"||$host[system_type_enum]=="NIDS"){
          $type=$host[system_type_enum];
        }elseif($host[user_type_enum]=="Firewall"){
          $type=$host[user_type_enum];
        }
        break;
      }
    }
    $parsed=sprintf("%s  <fw name=\"C%s\" type=\"%s\">\n",$parsed,$f,$type);
    $def_policy="open";
    foreach($data[net_model][access_rule] as $rule){

      if(($rule[host_id]==$f) and ($rule[chain_number]=="3")){

        $sstring=explode(",",$rule[source_ip_space_ip_ranges]);
        $src=explode("-",$sstring[0]);
        $source=implode(",",$src);

        $dstring=explode(",",$rule[target_ip_space_ip_ranges]);
        $destination=explode("-",$dstring[0]);
        $dest=implode(",",$destination);

        $services=explode(",",$rule[firewall_space_firewall_services]);
        $serv=explode("/",$services[0]);

        $sp=explode("-",$serv[0]);
        $sport=implode(",",$sp);

        $dp=explode("-",$serv[1]);
        $dport=implode(",",$dp);

        switch($serv[2]){
        case "TCP":
          $protocol="1,1";
          break;
        case "UDP":
          $protocol="2,2";
          break;
        case "ICMP":
          $protocol="3,3";
          break;
        case "ANY":
          $protocol="1,2";
          break;
        default:
          $protocol="1,2";
        }

        switch($rule[action_type_enum]){
        case "1":
          $dec="accept";
          break;
        case "2":
          $dec="deny";
          break;
        default:
          $dec="unknown";
        }

        if($rule[is_implied]=="true"){
          //we'll check whether is pointing out
          //to the component's default policy
          if(($source=="0.0.0.0,255.255.255.255") and
             ($dest=="0.0.0.0,255.255.255.255") and
             ($sport=="1,65535") and
             ($dport=="1,65535") and
             ($protocol=="1,2")
             ){
            if($dec=="deny"){
              $def_policy="close";
            }else{
              $def_policy="open";
            }
          }
        }else{
          $def_policy="open";
          $parsed=sprintf("%s   <rule>\n",$parsed);
          $parsed=sprintf("%s    <condition>\n",$parsed);
          $parsed=sprintf("%s     <subcondition>\n",$parsed);
          $parsed=sprintf("%s      <s>%s</s>\n",$parsed,$source);
          $parsed=sprintf("%s      <d>%s</d>\n",$parsed,$dest);
          $parsed=sprintf("%s      <sP>%s</sP>\n",$parsed,$sport);
          $parsed=sprintf("%s      <dP>%s</dP>\n",$parsed,$dport);
          $parsed=sprintf("%s      <p>%s</p>\n",$parsed,$protocol);
          $parsed=sprintf("%s     </subcondition>\n",$parsed);
          $parsed=sprintf("%s     <subcondition>\n",$parsed);
          $parsed=sprintf("%s     </subcondition>\n",$parsed);
          $parsed=sprintf("%s    </condition>\n",$parsed);
          $parsed=sprintf("%s    <decision>%s</decision>\n",$parsed,$dec);
          $parsed=sprintf("%s    <shadowing>false</shadowing>\n",$parsed);
          $parsed=sprintf("%s    <redundancy>false</redundancy>\n",$parsed);
          $parsed=sprintf("%s    <nids_misc>%s</nids_misc>\n",$parsed,$rule[nids_misc]);
          $parsed=sprintf("%s   </rule>\n",$parsed);
        }//else
      }//if
    }//foreach
    $parsed=sprintf("%s  <policy>%s</policy>\n",$parsed,$def_policy);
    $parsed=sprintf("%s  </fw>\n",$parsed);
  }//foreach firewall
  $parsed=sprintf("%s </rules>\n",$parsed);
  // ---------------------- access_rules ---------

  // ---------------------- zones ---------
  $parsed=sprintf("%s <zones>\n",$parsed);
  foreach($data[net_model][network] as $network){
    unset($range);
    unset($net);
    $id=$network[id];
    $zone[$id]=$network[name];
    $parsed=sprintf("%s  <zone name=\"%s\" id=\"Z%s\">\n",$parsed,$network[name],$network[id]);
    $parsed=sprintf("%s   <included>\n",$parsed);
    $parsed=sprintf("%s    %s/%s",$parsed,$network[ip_address],$network[net_mask]);
    if($network[included_ip_ranges]!=""){
      $i=0;
      $serie=explode(",",$network[included_ip_ranges]);
      foreach($serie as $s){
        $range=explode("-",$s);
        if(count($range)==1){
          $parsed=sprintf("%s,%s\n",$parsed,$s);
        }elseif(count($range)==2){
          $net[$i]=range2cidr($range[0],$range[1]);
          while($net[$i]==NULL){
              $range[1]=long2ip(ip2long($range[1])+1);
              $net[$i]=range2cidr($range[0],$range[1]);
          }
          $i++;
        }
      }
      $parsed=sprintf("%s,%s\n",$parsed,implode(",",$net));
    }else{
      $parsed=sprintf("%s\n",$parsed);
    }
    $parsed=sprintf("%s   </included>\n",$parsed);
    $parsed=sprintf("%s   <excluded>\n",$parsed);
    if($network[excluded_ip_ranges]!=""){
      $i=0;
      $serie=explode(",",$network[excluded_ip_ranges]);
      foreach($serie as $s){
        $range=explode("-",$s);
        if(count($range)==1){
          //$parsed=sprintf("%s    %s\n",$parsed,$s);
        }elseif(count($range)==2){
          $net[$i]=range2cidr($range[0],$range[1]);
          while($net[$i]==NULL){
              $range[1]=long2ip(ip2long($range[1])+1);
              $net[$i]=range2cidr($range[0],$range[1]);
          }
          $i++;
        }
      }
      $parsed=sprintf("%s    %s\n",$parsed,implode(",",$net));
    }
    $parsed=sprintf("%s   </excluded>\n",$parsed);
    $parsed=sprintf("%s  </zone>\n",$parsed);
  }//foreach

  $parsed=sprintf("%s </zones>\n",$parsed);
  // ---------------------- zones ---------

  // ---------------------- vulnerabilities ---------
  //   $parsed=sprintf("%s <vulnerabilities>\n",$parsed);
  //   foreach($data[net_model][ticket] as $ticket){
  //     if($ticket[type]=="VulnerabilityTicket"){
  //       $category=explode(" ",$ticket[host_os_name]);
  //       $parsed=sprintf("%s  <vulnerability id=\"%s\" category=\"%s\">\n",$parsed,$ticket[id],$category[0]);
  //       $parsed=sprintf("%s   <affects>%s</affects>\n",$parsed,long2ip($ticket[host_primary_ip_address]));
  //       $parsed=sprintf("%s   <description>%s</description>\n",$parsed,$ticket[title]);
  //       $parsed=sprintf("%s  </vulnerability>\n",$parsed);
  //     }
  //   }//foreach
  //   $parsed=sprintf("%s </vulnerabilities>\n",$parsed);
  // ---------------------- vulnerabilities ---------


  // ---------------------- connections ---------
  $parsed=sprintf("%s <connections>\n",$parsed);

  foreach($data[net_model][net_interface] as $network){
    $hid=$network[host_id];
    $nid=$network[network_id];
    if(isset($component[$hid]) and isset($zone[$nid])){
      $parsed=sprintf("%s  <adjacent host_id=\"C%s\" zone_id=\"Z%s\">\n",$parsed,$network[host_id],$network[network_id]);
      //$parsed=sprintf("%s   C%s,Z%s\n",$parsed,$component[$hid],$zone[$nid]);
      $parsed=sprintf("%s   C%s,Z%s\n",$parsed,$network[host_id],$network[network_id]);
      $parsed=sprintf("%s  </adjacent>\n",$parsed);
    }
  }//foreach

  $parsed=sprintf("%s </connections>\n",$parsed);
  // ---------------------- connections ---------


  $parsed=sprintf("%s</topology>\n",$parsed);

  if($generateOutput){
    $path = './top';
    if (!$handle = fopen($path."/".$savefilename, 'w')) {
      echo "Cannot open file (".$path."/".$savefilename.")";
      exit;
    }
    if (fwrite($handle, $parsed) === FALSE) {
      echo "Cannot write to file (".$path."/".$savefilename.")";
      exit;
    }
    echo "<BR> /* Ready to save the network model to file <a href=\"".$path."/".$savefilename."\">$savefilename</a> */<BR>";
    fclose($handle);
  }

  $end = my_microtime();
  printf("<BR> /* Translation process done in %f seconds. */<BR><BR>",round($end-$start2,5));
  printf("<BR><b> /* Whole process done in %f seconds. */</b><BR>",round($end-$start,5));
  unset($data);
  //$ini= memory_get_usage();
  //printf("<b> /* Memory allocated: %u (bytes)  ~ %u (kbytes) ~ %u (mbytes) */</b><BR><BR>",$ini, $ini/1024, $ini/(1024*1024));
  echo "<BR><table><TR><td width=\"50%\" align=\"center\">&nbsp;</td>";
  echo "<td><FORM method=post name=form action=\"genxml.php\" >";
  printf("<input type=\"hidden\" name=\"data\" value=\"%s\">",base64_encode($parsed));
  echo "<input type=\"button\" onclick=\"javascript:window.location.href='./gui.php'\" value=\"Clear and Reload\">";
  echo "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
  echo "<select name=\"generate\">";
  echo "<option value=\"save\">save XML</option>";
  echo "<option value=\"view\" selected=\"selected\">view XML</option>";
  echo "</select><input type=\"submit\" value=\"go\">";
  echo "</TD><td></td></TR></table>";
  echo "</form>";
  echo "</body></html>";
}//(1)parser([...])
//---------------------------------------------------------------------

//---------------------------------------------------------------------
//(2)postprocess([...])
function postprocess($path,$file,$generateOutput,$savefilename){

  //$ini= memory_get_usage();
  printf("<b> Memory Limit: </b> %sb <br>",get_cfg_var("memory_limit"));
  printf("<b> CPU Time Limit: </b> %ss <br>",get_cfg_var("max_execution_time"));
  //printf("<b> Memory Allocated: </b> %u (bytes)  ~ %u (kbytes) <BR><BR>",$ini, $ini/1024);

  echo "<BR>/* Unserializing <a href=\"$path/$file\">$file</a> ....";

  $start = my_microtime();
  $options = array('parseAttributes'=>true);
  $unserializer = &new XML_Unserializer($options);
  $result = $unserializer->unserialize($path."/".$file,true);
  $data = $unserializer->getUnserializedData();

  $end = my_microtime();
  printf("... done in %f seconds! */<BR>",round($end-$start,5));
  $start2 = my_microtime();

  foreach($data[vulnerabilities][vulnerability] as $v){
    for($i=0;$i<(count($data[zones][zone]));$i++){
      $ip=$v[affects];
      $zid=$data[zones][zone][$i][id];
      $included=$data[zones][zone][$i][included];
      $excluded=$data[zones][zone][$i][excluded];
      if(within($ip,$included,$excluded)){
        $data[zones][zone][$i][vulnerability][]=$v;
      }
    }
    $j++;
  }

  $xml_header="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  $parsed=sprintf("%s",$xml_header);
  $parsed=sprintf("%s<network_model>\n",$parsed);

  // ---------------------- components ---------
  $parsed=sprintf("%s <components>\n",$parsed);
  foreach($data[rules][fw] as $firewall){
    $parsed=sprintf("%s  <fw name=\"%s\" type=\"%s\">\n",$parsed,$firewall[name],$firewall[type]);
    foreach($firewall[rule] as $rule){
      $parsed=sprintf("%s   <rule>\n",$parsed);
      $parsed=sprintf("%s    <condition>\n",$parsed);
      for($i=0;$i<(count($rule[condition][subcondition])-1);$i++){
        $sub=$rule[condition][subcondition][$i];
        $parsed=sprintf("%s     <subcondition>\n",$parsed);
        $parsed=sprintf("%s      <s>%s</s>\n",$parsed,$sub[s]);
        $parsed=sprintf("%s      <d>%s</d>\n",$parsed,$sub[d]);
        $parsed=sprintf("%s      <sP>%s</sP>\n",$parsed,$sub[sP]);
        $parsed=sprintf("%s      <dP>%s</dP>\n",$parsed,$sub[dP]);
        $parsed=sprintf("%s      <p>%s</p>\n",$parsed,$sub[p]);
        $parsed=sprintf("%s     </subcondition>\n",$parsed);
      }
      $parsed=sprintf("%s     <subcondition>\n",$parsed);
      $parsed=sprintf("%s     </subcondition>\n",$parsed);
      $parsed=sprintf("%s    </condition>\n",$parsed);
      $parsed=sprintf("%s    <decision>%s</decision>\n",$parsed,$rule[decision]);
      $parsed=sprintf("%s    <shadowing>false</shadowing>\n",$parsed);
      $parsed=sprintf("%s    <redundancy>false</redundancy>\n",$parsed);
      $parsed=sprintf("%s    <nids_misc>%s</nids_misc>\n",$parsed,$rule[nids_misc]);
      $parsed=sprintf("%s   </rule>\n",$parsed);
    }//foreach
    $parsed=sprintf("%s  <policy>%s</policy>\n",$parsed,$firewall[policy]);
    $parsed=sprintf("%s  </fw>\n",$parsed);
  }//foreach
  $parsed=sprintf("%s </components>\n",$parsed);
  // ---------------------- components ---------

  // ---------------------- zones ---------
  $parsed=sprintf("%s <zones>\n",$parsed);
  foreach($data[zones][zone] as $z){
    unset($range);
    unset($net);
    $id=$network[id];
    $zone[$id]=$network[name];
    $parsed=sprintf("%s  <zone name=\"%s\">\n",$parsed,$z[id]);
    $parsed=sprintf("%s   <included>\n",$parsed);
    $parsed=sprintf("%s    %s",$parsed,$z[included]);
    $parsed=sprintf("%s   </included>\n",$parsed);
    $parsed=sprintf("%s   <excluded>\n",$parsed);
    $parsed=sprintf("%s    %s",$parsed,$z[excluded]);
    $parsed=sprintf("%s   </excluded>\n",$parsed);
    $parsed=sprintf("%s   <vulnerabilities>\n",$parsed);
    foreach($z[vulnerability] as $v){
      $parsed=sprintf("%s    <vulnerability id=\"%s\" category=\"%s\">\n",$parsed,$v[id],$v[category]);
      $parsed=sprintf("%s     <affects>%s</affects>\n",$parsed,$v[affects]);
      $parsed=sprintf("%s     <description>%s</description>\n",$parsed,$v[description]);
      $parsed=sprintf("%s    </vulnerability>\n",$parsed);
    }
    $parsed=sprintf("%s   </vulnerabilities>\n",$parsed);
    $parsed=sprintf("%s  </zone>\n",$parsed);
  }//foreach

  $parsed=sprintf("%s </zones>\n",$parsed);
  // ---------------------- zones ---------

  // ---------------------- routes ---------
  $i=0;
  foreach($data[zones][zone] as $zone){
    $point[$i]=$zone[id];
    $crosspoint[$zone[id]]=$i;
    $i++;
  }

  $nzones=$i;

  foreach($data[hosts][host] as $host){
    $point[$i]=$host[id];
    $crosspoint[$host[id]]=$i;
    $i++;
  }

  $npoints=$i;

  foreach($data[connections][adjacent] as $a){
    $hid=$crosspoint[$a[host_id]];
    $zid=$crosspoint[$a[zone_id]];
    $adjacent[$hid][$zid]=true;
  }

  for($i=0;$i<$npoints;$i++){
    for($j=0;$j<$npoints;$j++){
      $m[$i][$j]=0;
    }
  }

  for($i=0;$i<$nzones;$i++){
    for($j=$nzones;$j<$npoints;$j++){
      if(isset($adjacent[$j][$i])){
        $m[$j][$i]=1;
        $m[$i][$j]=1;
      }
    }
  }


  $parsed=sprintf("%s <routes>\n",$parsed);

  $graph = new graph($m);

  for($i=0;$i<($nzones-1);$i++){
    for($j=($i+1);$j<($nzones);$j++){
      $z1=$data[zones][zone][$i][id];
      $z2=$data[zones][zone][$j][id];
      unset($mr);
      $graph -> minimal_route($crosspoint[$z1],$crosspoint[$z2]);
      $z=0;
      for($y=0;$y<(count($graph->routes)-1);$y++){
        if($graph->routes[$y]>=$nzones){
          $mr[$z]=$point[$graph->routes[$y]];
          $z++;
        }
      }
      $parsed=sprintf("%s  <mr zone=\"%s,%s\">\n",$parsed,$z1,$z2);
      $parsed=sprintf("%s   <content> %s </content>\n",$parsed,implode(",",$mr));
      $parsed=sprintf("%s  </mr>\n",$parsed);
    }
  }

  $parsed=sprintf("%s </routes>\n",$parsed);
  // ---------------------- routes ---------


  $parsed=sprintf("%s</network_model>\n",$parsed);



  // ----------------------------
  $path = './net';

  if (!$handle = fopen($path."/".$savefilename, 'w')) {
    echo "Cannot open file (".$path."/".$savefilename.")";
    exit;
  }

  // Write $somecontent to our opened file.
  if (fwrite($handle, $parsed) === FALSE) {
    echo "Cannot write to file (".$path."/".$savefilename.")";
    exit;
  }

  echo "<BR> /* Ready to save minimal_routes to file <a href=\"".$path."/".$savefilename."\">$savefilename</a> */<BR>";

  fclose($handle);
  // ----------------------------

  $end = my_microtime();
  printf("<BR> /* Generation process done in %f seconds. */<BR><BR>",round($end-$start2,5));
  printf("<BR><b> /* Whole process done in %f seconds. */</b><BR>",round($end-$start,5));
  unset($data);
  //$ini= memory_get_usage();
  //printf("<b> /* Memory allocated: %u (bytes)  ~ %u (kbytes) ~ %u (mbytes) */</b><BR><BR>",$ini, $ini/1024, $ini/(1024*1024));
  echo "<BR><table><TR><td width=\"50%\" align=\"center\">&nbsp;</td>";
  echo "<td><FORM method=post name=form action=\"genxml.php\">";
  printf("<input type=\"hidden\" name=\"data\" value=\"%s\">",base64_encode($parsed));
  echo "<input type=\"button\" onclick=\"javascript:window.location.href='./gui.php'\" value=\"Clear and Reload\">";
  echo "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
  echo "<select name=\"generate\">";
  echo "<option value=\"save\">save XML</option>";
  echo "<option value=\"view\" selected=\"selected\">view XML</option>";
  echo "</select><input type=\"submit\" value=\"go\">";
  echo "</TD><td></td></TR></table>";
  echo "</body></html>";
}//(2)postprocess([...])
//---------------------------------------------------------------------

//-------------------------------------------------
//(3)detection_intra_component([...])
function detection_intra_component($path,$file,$generateOutput,$outputFilename,$view,$component){

  if($component=="none"){
    exit;
  }


  if($view=="all"){
    //$ini= memory_get_usage();
    printf("<b> Memory Limit: </b> %sb <br>",get_cfg_var("memory_limit"));
    printf("<b> CPU Time Limit: </b> %ss <br>",get_cfg_var("max_execution_time"));
    //printf("<b> Memory Allocated: </b> %u (bytes)  ~ %u (kbytes) <BR><BR>",$ini, $ini/1024);
    echo "<BR>/* Unserializing <a href=\"$path/$file\">$file</a> ....";
  }

  $start = my_microtime();
  $options = array('parseAttributes'=>true);
  $unserializer = &new XML_Unserializer($options);
  $result = $unserializer->unserialize($path."/".$file,true);
  $ini_data = $unserializer->getUnserializedData();
  unset($options);
  unset($unserializer);
  unset($result);

  $end = my_microtime();

  if($view=="all"){
    printf("... done in %f seconds! */<BR><BR>",round($end-$start,5));
  }

  foreach($ini_data[components][fw] as $fw){
    if($fw[name]==$component){
      $initialRules=$fw;
      $data=$fw;
      break;
    }
  }

  //unset($ini_data);

  echo "<BR><b>/* Processing intra-component audit to component $component */</b><BR><BR>";


  echo "<BR><BR>";
  echo "<b>/* initial rules */</b>";
  echo"<BR><BR>";
  showTable($data);

  //It is necessary to perform a pre-process to all the rules in order
  //to detect which fields are IPv4 valid addresses.

  //We first construct an associative array to indicate whether a
  //key-field is or is not a valid IPv4 address
  $IPfields=NULL;
  foreach($data[rule][0][condition][subcondition][0] as $key => $value){
    $value=explode(",",$data[rule][0][condition][subcondition][0][$key]);
    if(is_IPv4($value[0])){
      $field = array( $key  => 1);
    }else{
      $field = array( $key  => -1);
    }
    $IPfields=array_merge($IPfields,$field);
  }//foreach

  //We then perform a simple transformation from ipv4 to long numbers
  for($i=0;$i<count($data[rule]);$i++){
    for($j=0;$j<count($data[rule][$i][condition][subcondition]);$j++){
      foreach($data[rule][$i][condition][subcondition][$j] as $key => $value){
        $value=explode(",",$data[rule][$i][condition][subcondition][$j][$key]);
        if($IPfields[$key]==1){
          $ip[0]=ip2long($value[0]);
          $ip[1]=ip2long($value[1]);
          $data[rule][$i][condition][subcondition][$j][$key]=sprintf("%u,%u",$ip[0],$ip[1]);
        }//if
      }//foreach
    }//for_j
  }//for_i

  if(isset($ip)&&$view=="all"){
    echo "<BR>";
    echo "<b>/* Transformation from IPv4-dotted-format to long-integer-format */</b>";
    echo"<BR><BR>";
    showData($data);
    echo "<BR><BR>";
  }


  //MAIN-----------------------------------
  $start = my_microtime();
  //phase 1
  for($i=0;$i<(count($data[rule])-1);$i++){
    $step=$i+1;
    $rule=$i+1;
    if($view=="all"){
      echo "<b>/* phase 1, step = $step, i = $rule */</b><BR>";
    }

    for($j=$i+1;$j<(count($data[rule]));$j++){
      if ($data[rule][$i][decision]!=$data[rule][$j][decision]){
        $start = my_microtime();
        $data[rule][$j]=exclusion($data[rule][$j],$data[rule][$i],$i,$j);
        $end = my_microtime();
      }//if
      if(emptyCondition($data[rule][$j])){
        $data[rule][$j][shadowing]="true";
      }//if
    }//for
    if($view=="all"){
      showData($data);
      echo"<BR><BR>";
    }
  }//for_i
  //phase 2
  for($i=0;$i<(count($data[rule]));$i++){
    $step=$i+1;
    $rule=$i+1;
    $tred=testRedundancy($data[rule],$i);
    if($view=="all"){
      echo "<b>/* phase 2, step = $step, i = $rule */</b><BR>";
      if($tred!=false){
        echo "<b>/* testRedundancy(R$rule) == true */</b>";
      }else{
        echo "<b>/* testRedundancy(R$rule) == false */</b>";
      }
      echo"<BR>";
    }

    if($tred!=false){
      $data[rule][$i][condition][subcondition]=",";
      $data[rule][$i][redundancy]="true";
      $data[rule][$i][excluded_by]=$tred;
    }else{
      for($j=$i+1;$j<(count($data[rule]));$j++){
        if ($data[rule][$i][decision]==$data[rule][$j][decision]){
          $data[rule][$j]=exclusion($data[rule][$j],$data[rule][$i],$i,$j);
        }//if
        if(emptyCondition($data[rule][$j]) && $data[rule][$j][redundancy]!="true"){
          $data[rule][$j][shadowing]="true";
        }//if
      }//for
    }//else

    if($view=="all"){
      showData($data);
      echo"<BR><BR>";
      //showWarnings($data);
      //echo"<BR><BR>";
    }
  }
  $end = my_microtime();
  //MAIN-----------------------------------

  if($view=="all"){
    echo "<b>/* resulting rules */</b>";
    echo"<BR>";
    showResults($data);
  }

  //It is necessary to post-process all the rules in order to detect
  //which fields were IPv4 valid address.
  if(isset($ip)){
    for($i=0;$i<count($data[rule]);$i++){
      for($j=0;$j<(count($data[rule][$i][condition][subcondition])-1);$j++){
        foreach($data[rule][$i][condition][subcondition][$j] as $key => $value){
          $value=explode(",",$data[rule][$i][condition][subcondition][$j][$key]);
          if($IPfields[$key]==1){
            $ipString[0]=long2ip($value[0]);
            $ipString[1]=long2ip($value[1]);
            $data[rule][$i][condition][subcondition][$j][$key]=sprintf("%s,%s",$ipString[0],$ipString[1]);
          }//if
        }//foreach
      }//for_j
    }//for_i

    if($view=="all"){
      echo "<BR><BR><BR>";
      echo "<b><font color=black>/* Transformation from long-integer-format to IPv4-dotted-format */</b></font>";
      echo"<BR><BR>";
      showResults($data);
      echo "<BR>";
      echo "Default Policy:$data[policy]";
    }
  }

  echo"<BR><BR>";
  $nwarnings = showWarnings($data);

  if($nwarnings>2){
    echo "<BR><BR><b><font color=\"red\">$nwarnings warnings have been found!</font></b>";
  }

  echo "<BR><BR><b>/* resulting rules */</b><BR><BR>";


  $rulestabular="<img src=\"img/banner-intra.png\"><table border=2 width=\"100\%\"><tr align=\"center\">"
    ."<td><b>Order</b><td><b>Protocol</b></td>"
    ."<td><b>srcAddr</b></td><td><b>srcPort</b></td>"
    ."<td><b>destAddr</b></td><td><b>destPort</b></td>"
    ."<td><b>Action</b></td>"
    ."<td width=\"25\"><img src=\"img/shadowing.png\"></td>"
    ."<td width=\"25\"><img src=\"img/redundancy.png\"></td>"
    ."</tr>";

  $i=0;
  if(count($data[rule])>1){
    for($i=0;$i<count($data[rule]);$i++){
      $rulestabular .= "<tr align=\"center\">";
      $action=$data[rule][$i][decision];
      $shadowed=$data[rule][$i][shadowing];
      $redundant=$data[rule][$i][redundancy];
      for($j=0;$j<(count($data[rule][$i][condition][subcondition]));$j++){

        //if_condition_is_empty
        if(count($data[rule][$i][condition][subcondition])==1){
          $emptyrule=$initialRules[rule][$i][condition][subcondition][0];

          $rulestabular .= "<tr align=\"center\">";
          $rulestabular .= "<td><b>".($i+1)."</b></td>";
          //protocol
          if($emptyrule[p]=="1,1"){
            $rulestabular .= "<td><b>tcp</b></td>";
          }elseif($emptyrule[p]=="2,2"){
            $rulestabular .= "<td><b>udp</b></td>";
          }elseif($emptyrule[p]=="1,2"){
            $rulestabular .= "<td><b>any</b></td>";
          }else{
            $rulestabular .= "<td>icmp</td>";
          }
          //sourceAddr
          $rulestabular .= "<td><b>".$emptyrule[s]."</b></td>";
          //sourcePort
          if($emptyrule[sP]=="1,65535"){
            $rulestabular .= "<td><b>any</b></td>";
          }else{
            $rulestabular .= "<td><b>&nbsp;".$emptyrule[sP]."</b></td>";
          }
          //destAddr
          $rulestabular .= "<td><b>".$emptyrule[d]."</b></td>";
          //destPort
          if($emptyrule[dP]=="1,65535"){
            $rulestabular .= "<td><b>any</b></td>";
          }else{
            $rulestabular .= "<td><b>&nbsp;".$emptyrule[dP]."</b></td>";
          }

          //action
          if($data[type]=="NIDS"){
            if($action=="accept"){
              $rulestabular .= "<td>pass</td>";
            }elseif($action=="deny"){
              $rulestabular .= "<td>alert</td>";
            }
          }else{
            //$rulestabular .= "<td>".$action."</td>";
            $rulestabular .= "<td>".$action."</td>";
          }


          //anomalies
          $rulestabular .= "<td><b>&nbsp;";
          if($shadowed=="true"){
            unset($excList);
            unset($nexc);
            $nexc=0;
            $excList=array_unique(explode(",",$data[rule][$i][excluded_by]));

            foreach($excList as $ee){
              if(!$nexc){
                $rulestabular .= $ee;
                $nexc++;
              }else{
                $rulestabular .= "<BR>&nbsp;".$ee;
                $nexc++;
              }
            }
          }
          $rulestabular .= "</b></td>";

          $rulestabular .= "<td><b>&nbsp;";
          if($redundant=="true"){
            unset($excList);
            unset($nexc);
            $nexc=0;
            $excList=array_unique(explode(",",$data[rule][$i][excluded_by]));
            foreach($excList as $ee){
              if(!$nexc){
                $rulestabular .= $ee;
                $nexc++;
              }else{
                $rulestabular .= "<BR>&nbsp;".$ee;
                $nexc++;
              }
            }
            //$rulestabular .= $data[rule][$i][excluded_by];
          }
          $rulestabular .= "</b></td>";
          $rulestabular .= "</tr>";
        }else{
          if($j<count($data[rule][$i][condition][subcondition])-1){
            $rulestabular .= "<tr align=\"center\">";
            $subrule=$data[rule][$i][condition][subcondition][$j];
            if(count($data[rule][$i][condition][subcondition])==2){
              $rulestabular .= "<td>".($i+1)."</td>";
            }else{
              $rulestabular .= "<td>".($i+1).",".($j+1)."</td>";
            }

            //protocol
            if($subrule[p]=="1,1"){
              $rulestabular .= "<td>tcp</td>";
            }elseif($subrule[p]=="2,2"){
              $rulestabular .= "<td>udp</td>";
            }elseif($subrule[p]=="1,2"){
              $rulestabular .= "<td>any</td>";
            }else{
              $rulestabular .= "<td>icmp</td>";
            }
            //sourceAddr
            $rulestabular .= "<td>&nbsp;".$subrule[s]."</td>";
            //sourcePort
            if($subrule[sP]=="1,65535"){
              $rulestabular .= "<td>any</td>";
            }else{
              $rulestabular .= "<td>&nbsp;".$subrule[sP]."</td>";
            }

            //destAddr
            $rulestabular .= "<td>&nbsp;".$subrule[d]."</td>";

            //destPort
            if($subrule[dP]=="1,65535"){
              $rulestabular .= "<td>any</td>";
            }else{
              $rulestabular .= "<td>&nbsp;".$subrule[dP]."</td>";
            }

            //action
            if($data[type]=="NIDS"){
              if($action=="accept"){
                $rulestabular .= "<td>pass</td>";
              }elseif($action=="deny"){
                $rulestabular .= "<td>alert</td>";
              }
            }else{
              //$rulestabular .= "<td>".$action."</td>";
              $rulestabular .= "<td>".$action."</td>";
            }



            //anomalies
            $rulestabular .= "<td>&nbsp;</td>";
            $rulestabular .= "<td>&nbsp;</td>";
            $rulestabular .= "</tr>";
          }
        }
      }
    }//for
  }//if

  //default
  if($data[type]=="NIDS"){
    if($data[policy]=="open"){
      $action="pass";
    }elseif($data[policy]=="close"){
      $action="alert";
    }
  }else{
    if($data[policy]=="open"){
      $action="accept";
    }elseif($data[policy]=="close"){
      $action="deny";
    }
  }


  $rulestabular .= "<tr align=\"center\">";
  $rulestabular .= "<td>".($i+1)."</td>";
  //protocol
  $rulestabular .= "<td>any</td>";
  //sourceAddr
  $rulestabular .= "<td>any</td>";
  //sourcePort
  $rulestabular .= "<td>any</td>";
  //destAddr
  $rulestabular .= "<td>any</td>";
  //destPort
  $rulestabular .= "<td>any</td>";
  //action
  $rulestabular .= "<td>".$action."</td>";
  //anomalies
  $rulestabular .= "<td>&nbsp;</td>";
  $rulestabular .= "<td>&nbsp;</td>";
  $rulestabular .= "</tr>";
  $rulestabular .= "</table>";

  echo "$rulestabular";


  //$warningAlert=sprintf("  Intra-component audit to component $component. \\n",$component);
  //$warningAlert=sprintf("%s ----------------------------------------------------------  \\n",$warningAlert);

  if($nwarnings==0){
    $warningAlert=sprintf("%s  No anomalies have been found.",$warningAlert);
  }elseif($nwarnings==1){
    $warningAlert=sprintf("%s  1 anomaly has been found.",$warningAlert);
  }elseif($nwarnings>1){
    $warningAlert=sprintf("%s  %d anomalies have been found.",$warningAlert,$nwarnings);
  }


//   if($view=="all"){
     echo"<BR><BR>";
     printf("<BR><b> /* Whole process done in %f seconds. */</b><BR>",round($end-$start,5));
     //$ini= memory_get_usage();
     //printf("<b> /* Memory allocated: %u (bytes)  ~ %u (kbytes) */</b><BR><BR>",$ini, $ini/1024);
//   }

  if($generateOutput){

    $xml_header="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    $parsed=sprintf("%s",$xml_header);
    $parsed=sprintf("%s<network_model>\n",$parsed);

    // ---------------------- components ---------
    $parsed=sprintf("%s <components>\n",$parsed);
    foreach($ini_data[components][fw] as $firewall){
      $parsed=sprintf("%s  <fw name=\"%s\" type=\"%s\">\n",$parsed,$firewall[name],$firewall[type]);
      if($firewall[name]==$data[name]){
        $rules=$data[rule];
      }else{
        $rules=$firewall[rule];
      }
      foreach($rules as $rule){
        if(count($rule[condition][subcondition])>1){
          for($i=0;$i<(count($rule[condition][subcondition])-1);$i++){
            $sub=$rule[condition][subcondition][$i];
            $parsed=sprintf("%s   <rule>\n",$parsed);
            $parsed=sprintf("%s    <condition>\n",$parsed);
            $parsed=sprintf("%s     <subcondition>\n",$parsed);
            $parsed=sprintf("%s      <s>%s</s>\n",$parsed,$sub[s]);
            $parsed=sprintf("%s      <d>%s</d>\n",$parsed,$sub[d]);
            $parsed=sprintf("%s      <sP>%s</sP>\n",$parsed,$sub[sP]);
            $parsed=sprintf("%s      <dP>%s</dP>\n",$parsed,$sub[dP]);
            $parsed=sprintf("%s      <p>%s</p>\n",$parsed,$sub[p]);
            $parsed=sprintf("%s     </subcondition>\n",$parsed);
            $parsed=sprintf("%s     <subcondition>\n",$parsed);
            $parsed=sprintf("%s     </subcondition>\n",$parsed);
            $parsed=sprintf("%s    </condition>\n",$parsed);
            $parsed=sprintf("%s    <decision>%s</decision>\n",$parsed,$rule[decision]);
            $parsed=sprintf("%s    <shadowing>false</shadowing>\n",$parsed);
            $parsed=sprintf("%s    <redundancy>false</redundancy>\n",$parsed);
            $parsed=sprintf("%s    <nids_misc>%s</nids_misc>\n",$parsed,$rule[nids_misc]);
            $parsed=sprintf("%s   </rule>\n",$parsed);
          }
        }//if
      }//foreach
      $parsed=sprintf("%s  <policy>%s</policy>\n",$parsed,$firewall[policy]);
      $parsed=sprintf("%s  </fw>\n",$parsed);
    }//foreach
    $parsed=sprintf("%s </components>\n",$parsed);
    // ---------------------- components ---------

    // ---------------------- zones ---------
    $parsed=sprintf("%s <zones>\n",$parsed);
    foreach($ini_data[zones][zone] as $z){
      unset($range);
      unset($net);
      $id=$network[id];
      $zone[$id]=$network[name];
      $parsed=sprintf("%s  <zone name=\"%s\">\n",$parsed,$z[name]);
      $parsed=sprintf("%s   <included>",$parsed);
      $parsed=sprintf("%s%s",$parsed,$z[included]);
      $parsed=sprintf("%s</included>\n",$parsed);
      $parsed=sprintf("%s   <excluded>",$parsed);
      $parsed=sprintf("%s%s",$parsed,$z[excluded]);
      $parsed=sprintf("%s</excluded>\n",$parsed);
      $parsed=sprintf("%s   <vulnerabilities>\n",$parsed);
      foreach($z[vulnerability] as $v){
        $parsed=sprintf("%s    <vulnerability id=\"%s\" category=\"%s\">\n",$parsed,$v[id],$v[category]);
        $parsed=sprintf("%s     <affects>%s</affects>\n",$parsed,$v[affects]);
        $parsed=sprintf("%s     <description>%s</description>\n",$parsed,$v[description]);
        $parsed=sprintf("%s    </vulnerability>\n",$parsed);
      }
      $parsed=sprintf("%s   </vulnerabilities>\n",$parsed);
      $parsed=sprintf("%s  </zone>\n",$parsed);
    }//foreach

    $parsed=sprintf("%s </zones>\n",$parsed);
    // ---------------------- zones ---------

    $parsed=sprintf("%s <routes>\n",$parsed);
    // ---------------------- routes ---------
    foreach($ini_data[routes][mr] as $mr){
      $parsed=sprintf("%s  <mr zone=\"%s\">\n",$parsed,$mr[zone]);
      $parsed=sprintf("%s   <content>%s</content>\n",$parsed,$mr[content]);
      $parsed=sprintf("%s  </mr>\n",$parsed);
    }
    $parsed=sprintf("%s </routes>\n",$parsed);
    // ---------------------- routes ---------
    $parsed=sprintf("%s</network_model>\n",$parsed);


    echo "<BR><BR><table><TR><td width=\"55%\">&nbsp;</td>\n";
    echo "<td><FORM method=post name=form action=\"genxml.php\">\n";
    printf("<input type=\"hidden\" name=\"data\" value=\"%s\">\n",base64_encode($parsed));
    printf("<input type=\"hidden\" name=\"component\" value=\"%s\">\n",$data[name]);
    printf("<input type=\"hidden\" name=\"outputFilename\" value=\"%s\">\n",$outputFilename);
    printf("<input type=\"hidden\" name=\"updateFilename\" value=\"%s/%s\">\n",$path,$file);

    echo "&nbsp;&nbsp;";
    echo "<select name=\"generate\">";
    echo "<option value=\"view\">view single XML</option>";
    echo "<option value=\"save\">save single XML</option>";
    echo "<option value=\"update\" selected=\"selected\">update Network model</option>";
    if($nwarnings==0){
      if($data[type]=="Firewall"){
        echo "<option value=\"netfilter\" selected=\"selected\">translate to Netfilter</option>";
      }else{
        echo "<option value=\"snort\" selected=\"selected\">translate to Snort</option>";
      }
    }else{
      if($data[type]=="Firewall"){
        echo "<option value=\"netfilter\">translate to Netfilter</option>";
      }else{
        echo "<option value=\"snort\">translate to Snort</option>";
      }
    }

    if($data[type]=="Firewall"){
      echo "<option value=\"saveNetfilter\">translate to Netfilter and save</option>";
    }else{
      echo "<option value=\"saveSnort\">translate to Snort and save</option>";
    }

    echo "</select>&nbsp;<input type=\"submit\" value=\"go\">";
    echo "</TD><td></td></TR></table>";
  }//if_generate_output

  //alert, confirm and prompt
  printf("<script languaje=\"javascript\">window.alert(\"%s\");</script><BR>",$warningAlert);

}//(3)detection_intra_component([...])
//---------------------------------------------------------------

//---------------------------------------------------------------
//(4)detection-inter-component([...])
function detection_inter_component($path,$file,$view){

  $wcolor="red";

  //$ini= memory_get_usage();
  printf("<b> Memory Limit: </b> %sb <br>",get_cfg_var("memory_limit"));
  printf("<b> CPU Time Limit: </b> %ss <br>",get_cfg_var("max_execution_time"));
  //printf("<b> Memory Allocated: </b> %u (bytes)  ~ %u (kbytes) <BR><BR>",$ini, $ini/1024);

  echo "<BR>/* Unserializing <a href=\"$path/$file\">$file</a> ....";

  $start = my_microtime();
  $options = array('parseAttributes'=>true);
  $unserializer = &new XML_Unserializer($options);
  $result = $unserializer->unserialize($path."/".$file,true);
  $data = $unserializer->getUnserializedData();
  unset($options);
  unset($unserializer);
  unset($result);
  $end = my_microtime();
  printf("... done in %f seconds! */<BR><BR>",round($end-$start,5));

  if(true){
    echo "<img src=\"img/hr.gif\" border=\"0\" height=\"2\" width=\"100%\" align=\"center\"><br><br>";
    //......................................................................
    //components............................................................
    $debugStr="";
    $warningStr="";
    $nwarnings=0;
    $debugStr=sprintf("%s<BR>Components:<BR>",$debugStr);
    echo "";
    foreach($data[components][fw] as $fw){
      $connections=Null;
      $debugStr=sprintf("%s&nbsp;&nbsp;&nbsp;&nbsp;<i>%s</i><BR>",$debugStr,$fw[name]);
    }
    //......................................................................
    //zones ................................................................
    $debugStr=sprintf("%s<BR>Zones:<BR>",$debugStr);

    foreach($data[zones][zone] as $z){
      $debugStr=sprintf("%s&nbsp;&nbsp;&nbsp;&nbsp;<i>%s:%s</i><BR>",$debugStr,$z[name],$z[included]);
    }
    //......................................................................
    //routes ...............................................................
    $debugStr=sprintf("%s<BR>Minimal Routes:<BR>",$debugStr);

    foreach($data[routes][mr] as $mr){
      $debugStr=sprintf("%s&nbsp;&nbsp;&nbsp;&nbsp;<i>MR(%s)={%s}</i><BR>",$debugStr,$mr[zone],$mr[content]);
    }
  }//if_true

  $debugStr=sprintf("%s<BR>",$debugStr);


  //------------------------------------------------------------------------
  //Transformation from IPv4-dotted-format to long-integer-format
  //
  for($fi=0;$fi<count($data[components][fw]);$fi++){
    //It is necessary to perform a pre-process to all the rules in order
    //to detect which fields are IPv4 valid addresses.

    //We first construct an associative array to indicate whether a
    //key-field is or is not a valid IPv4 address
    $IPfields=NULL;
    foreach($data[components][fw][$fi][rule][0][condition][subcondition][0] as $key => $value){
      $value=explode(",",$data[components][fw][$fi][rule][0][condition][subcondition][0][$key]);
      if(is_IPv4($value[0])){
        $field = array( $key  => 1);
      }else{
        $field = array( $key  => -1);
      }
      $IPfields=array_merge($IPfields,$field);
    }//foreach

    //We then perform a simple transformation from ipv4 to long numbers
    for($i=0;$i<count($data[components][fw][$fi][rule]);$i++){
      for($j=0;$j<count($data[components][fw][$fi][rule][$i][condition][subcondition]);$j++){
        foreach($data[components][fw][$fi][rule][$i][condition][subcondition][$j] as $key => $value){
          $value=explode(",",$data[components][fw][$fi][rule][$i][condition][subcondition][$j][$key]);
          if($IPfields[$key]==1){
            $ip[0]=ip2long($value[0]);
            $ip[1]=ip2long($value[1]);
            $data[components][fw][$fi][rule][$i][condition][subcondition][$j][$key]=sprintf("%u,%u",$ip[0],$ip[1]);
          }//if
        }//foreach
      }//for_j
    }//for_i
  }
  //
  //Transformation from IPv4-dotted-format to long-integer-format
  //------------------------------------------------------------------------


  $debugStr=sprintf("%s%s",$debugStr,'<BR><img src="img/hr.gif" border="0" height="2" width="100%" align="center"><br>');
  $debugStr=sprintf("%s<BR>/*InterFw analysis */<BR><BR>",$debugStr);

  $start = my_microtime();

  foreach($data[components][fw] as $fw){

    $debugStr=sprintf("%s%s",$debugStr,'<img src="img/hr.gif" border="0" height="2" width="100%" align="center"><br><br>');
    $debugStr=sprintf("%s<b>Component[%s]</b>&nbsp;&nbsp;(%s)<BR>",$debugStr,$fw[name],$fw[type]);
    $debugStr=sprintf("%s%s",$debugStr,showData_inter($fw));
    $debugStr=sprintf("%s<br>Default-policy = %s<BR>",$debugStr,$fw[policy]);


    for($i=0;$i<count($fw[rule]);$i++){

      $emptyU=false;
      $emptyD=false;

      if(isset($Zs)){
        unset($Zs);
      }
      if(isset($Zd)){
        unset($Zd);
      }
      $Zs=Null;
      $Zd=Null;

      $Zs=obtainZs($data[zones],$fw[rule][$i]);
      $Zd=obtainZd($data[zones],$fw[rule][$i]);

      $debugStr=sprintf("%s<BR><b>%s{R%d}:</b><BR>Rule=",$debugStr,$fw[name],($i+1));
      $debugStr=sprintf("%s%s",$debugStr,showRule($fw[rule][$i]));


      if((count($Zs)>1) or (count($Zd)>1)){
        $debugStr=sprintf("%s<BR>Zs={%s}",$debugStr,implode(",",$Zs));
        $debugStr=sprintf("%s<BR>Zd={%s}",$debugStr,implode(",",$Zd));
        $debugStr=sprintf("%s<BR>&nbsp;<font color=\"green\"><B> -> WARNING --> The analysis of this rule is wrong since:</B></font>",$debugStr);
        if(count($Zs)>1){
          $debugStr=sprintf("%s<BR>&nbsp;<font color=\"green\"><B><b> &nbsp;-> Zs includes more than one zone!! </B></b></font>",$debugStr);
        }else{
          $debugStr=sprintf("%s<BR>&nbsp;<font color=\"green\"><B><b> &nbsp;-> Zd includes more than one zone!! </B></b></font>",$debugStr);
        }
      }elseif((count($Zs) < 1) or (count($Zd) < 1)){
        $debugStr=sprintf("%s<BR>Zs={%s}",$debugStr,implode(",",$Zs));
        $debugStr=sprintf("%s<BR>Zd={%s}",$debugStr,implode(",",$Zd));
        $debugStr=sprintf("%s<BR>&nbsp;<font color=\"green\"><B> -> WARNING --> The analysis of this rule is wrong since:</B></font>",$debugStr);
        if(count($Zs) < 1){
          $debugStr=sprintf("%s<BR>&nbsp;<font color=\"green\"><B><b> &nbsp;-> Zs is empty!!</B></b></font>",$debugStr);
        }else{
          $debugStr=sprintf("%s<BR>&nbsp;<font color=\"green\"><B><b> &nbsp;-> Zd is empty!!</B></b></font>",$debugStr);
        }
      }

      echo "<script>";
      echo "function showWarning(element) {";
      echo "document.poppedLayer = eval('document.getElementById(element)');";
      echo "if(document.poppedLayer.style.visibility == \"visible\"){document.poppedLayer.style.visibility = \"hidden\";}";
      echo "else{document.poppedLayer.style.visibility = \"visible\";}";
      echo "}";
      echo "</script>";

      for($j=0;$j<count($Zs);$j++){
        for($k=0;$k<count($Zd);$k++){
          $debugStr=sprintf("%s<BR>Zs={%s}",$debugStr,$Zs[$j]);
          $debugStr=sprintf("%s<BR>Zd={%s}",$debugStr,$Zd[$k]);
          //------------------------------------------------------
          //CASE 1
          if(($Zs[$j]==$Zd[$k])&&($fw[rule][$i][decision]=="accept")){
            $debugStr=sprintf("%s%s",$debugStr,'<BR>&nbsp;<font color=red><B><b> -> Irrelevance [both Zs and Zd are the same zone]</B></b></font>');
            $warningStr=sprintf("%s<BR><a href=\"javascript:showWarning('%s{R%d}');\">%s{R%d}</a>:%s",$warningStr,$fw[name],($i+1),$fw[name],($i+1),'&nbsp;<font color=red><B><b> -> Irrelevance [both Zs and Zd are the same zone]</B></b></font>');
            $warningStr=sprintf("%s<div id='%s{R%d}' style='position:relative; visibility: visible'>",$warningStr,$fw[name],($i+1));
            $warningStr=sprintf("%s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
            $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub></div>",$warningStr,$fw[name],($i+1),showRule($fw[rule][$i]));
            $nwarnings++;
          }elseif($Zs[$j]!=$Zd[$k]){
         //
         //CASE 1
         //------------------------------------------------------

            //FIXME:we should change $p by $P, where $p would be
            //just an element of $P, within a foreach($P as $p) ...
            $p=getPaths($data[routes][mr],$Zs[$j],$Zd[$k]);
            if($p!=NULL){

              //------------------------------------------------------
              //CASE 2
              //
              $debugStr=sprintf("%s<BR>PATH={%s}",$debugStr,$p);
              if((!inside($fw[name],$p))&&($fw[rule][$i][decision]=="accept")){
                $debugStr=sprintf("%s%s%s%s",$debugStr,'<BR>&nbsp;<font color=red><B><b> -> Irrelevance [',$fw[name],' is not in the path]</B></b></font>');
                $warningStr=sprintf("%s<BR><a href=\"javascript:showWarning('%s{R%d}');\">%s{R%d}</a>:%s%s%s",$warningStr,$fw[name],($i+1),$fw[name],($i+1),'&nbsp;<font color=red><B><b> -> Irrelevance [',$fw[name],' is not in the path]</B></b></font>');
                $warningStr=sprintf("%s<div id='%s{R%d}' style='position:relative; visibility: visible'>",$warningStr,$fw[name],($i+1));
                $warningStr=sprintf("%s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub></div>",$warningStr,$fw[name],($i+1),showRule($fw[rule][$i]));
                $nwarnings++;
              }elseif(inside($fw[name],$p)){
             //
             //CASE 2
             //------------------------------------------------------

                //------------------------------------------------------
                //CASE 3

                $path_u=getHeader($p,$fw[name]);
                if($path_u[0]!=NULL){
                  $pathU=implode(",",$path_u);
                  $debugStr=sprintf("%s<BR>PATH_U={%s}",$debugStr,$pathU);

                  //foreach($path_u as $fw_name){
                  //we check just the last component of path_u
                  unset($fw_name);
                  $fw_name=$path_u[count($path_u)-1];
                    $fw_u=getFirewall($fw_name,$data[components][fw]);
                    $Rua=obtainCorrelatedRules($fw_u,$fw[rule][$i],"accept");
                    $Rud=obtainCorrelatedRules($fw_u,$fw[rule][$i],"deny");

//                     if($Rua[0]!=NULL){
//                       $debugStr=sprintf("%s<BR><font color=green>Rua with %s is not empty!!!</font>",$debugStr,$fw_name);
//                     }else{
//                       $debugStr=sprintf("%s<BR><font color=green>Rua with %s is empty!!!</font>",$debugStr,$fw_name);
//                     }
//                     if($Rud[0]!=NULL){
//                       $debugStr=sprintf("%s<BR><font color=green>Rud with %s is not empty!!!</font>",$debugStr,$fw_name);
//                     }else{
//                       $debugStr=sprintf("%s<BR><font color=green>Rud with %s is empty!!!</font>",$debugStr,$fw_name);
//                     }

                    $RuaTestComplient[0]=$fw[rule][$i];
                    $RuaCounter=1;
                    unset($anomaliesWithRua);
                    foreach($Rua as $rule){
                      $anomaliesWithRua[($RuaCounter-1)]=$rule[shadowing];
                      $RuaTestComplient[$RuaCounter]=$rule;
                      $RuaCounter++;
                    }
                    $RudTestComplient[0]=$fw[rule][$i];
                    $RudCounter=1;
                    unset($anomaliesWithRud);
                    foreach($Rud as $rule){
                      $anomaliesWithRud[($RudCounter-1)]=$rule[shadowing];
                      $RudTestComplient[$RudCounter]=$rule;
                      $RudCounter++;
                    }

                    if($fw[rule][$i][decision]=="deny"){

                      //------------------------------------------------------
                      //CASE 3.1

                      if(($Rua[0]==NULL)&&($Rud[0]==NULL)&&($fw_u[policy]=="open")){
                        //------------------------------------------------------
                        //CASE 3.1.5
                        $debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=red><B> -> Full Misconnection with %s{policy}</B></font>",$debugStr,$fw_name);
                        $warningStr=sprintf("%s<BR><a href=\"javascript:showWarning('%s{R%d}');\">%s{R%d}</a>:&nbsp;&nbsp;<font color=red><B> -> Full Misconnection with %s{policy}</B></font>",$warningStr,$fw[name],($i+1),$fw[name],($i+1),$fw_name);
                        $warningStr=sprintf("%s<div id='%s{R%d}' style='position:relative; visibility: visible'>",$warningStr,$fw[name],($i+1));
                        $warningStr=sprintf("%s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                        $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub></div>",$warningStr,$fw[name],($i+1),showRule($fw[rule][$i]));
                        $nwarnings++;
                      }elseif($Rua[0]!=NULL){
                        $RuaString=implode(",R",$anomaliesWithRua);
                        if(testRedundancy_inter($RuaTestComplient,0)){
                          //------------------------------------------------------
                          //CASE 3.1.1
                          $debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=red><B><b> -> Full Misconnection with %s{R%s}</B></b></font>",$debugStr,$fw_name,$RuaString);
                          $warningStr=sprintf("%s<BR><a href=\"javascript:showWarning('%s{R%d}');\">%s{R%d}</a>:&nbsp;&nbsp;<font color=red><B><b> -> Full Misconnection with %s{R%s}</B></b></font>",$warningStr,$fw[name],($i+1),$fw[name],($i+1),$fw_name,$RuaString);
                          $warningStr=sprintf("%s<div id='%s{R%d}' style='position:relative; visibility: visible'>",$warningStr,$fw[name],($i+1));
                          $warningStr=sprintf("%s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                          $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub>",$warningStr,$fw[name],($i+1),showRule($fw[rule][$i]));
                          foreach(explode(",",$RuaString) as $CRua){
                            foreach(explode("R",$CRua) as $CRuaIndex){
                              if($CRuaIndex!=0){
                                $warningStr=sprintf("%s<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                                $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub>",$warningStr,$fw_name,$CRuaIndex,showRule($fw_u[rule][($CRuaIndex-1)]));
                              }
                            }
                          }
                          $warningStr=sprintf("%s</div>",$warningStr);
                          $nwarnings++;
                        }else{
                          //------------------------------------------------------
                          //CASE 3.1.2
                          $debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=red><B><b> -> Partial Misconnection with %s{R%s}</B></b></font>",$debugStr,$fw_name,$RuaString);
                          $warningStr=sprintf("%s<BR><a href=\"javascript:showWarning('%s{R%d}');\">%s{R%d}</a>:&nbsp;&nbsp;<font color=red><B><b> -> Partial Misconnection with %s{R%s}</B></b></font>",$warningStr,$fw[name],($i+1),$fw[name],($i+1),$fw_name,$RuaString);
                          $warningStr=sprintf("%s<div id='%s{R%d}' style='position:relative; visibility: visible'>",$warningStr,$fw[name],($i+1));
                          $warningStr=sprintf("%s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                          $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub>",$warningStr,$fw[name],($i+1),showRule($fw[rule][$i]));
                          foreach(explode(",",$RuaString) as $CRua){
                            foreach(explode("R",$CRua) as $CRuaIndex){
                              if($CRuaIndex!=0){
                                $warningStr=sprintf("%s<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                                $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub>",$warningStr,$fw_name,$CRuaIndex,showRule($fw_u[rule][($CRuaIndex-1)]));
                              }
                            }
                          }
                          $warningStr=sprintf("%s</div>",$warningStr);
                          $nwarnings++;
                        }//if_not_test_redundancy
                      }elseif($Rud[0]!=NULL){
                        $RudString=implode(",R",$anomaliesWithRud);
                        if(testRedundancy_inter($RudTestComplient,0)){
                          //------------------------------------------------------
                          //CASE 3.1.3
                          echo "";
                          $debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=red><B> -> Full Redundancy with %s{R%s}</B></font>",$debugStr,$fw_name,$RudString);
                          $warningStr=sprintf("%s<BR><a href=\"javascript:showWarning('%s{R%d}');\">%s{R%d}</a>:&nbsp;&nbsp;<font color=red><B> -> Full Redundancy with %s{R%s}</B></font>",$warningStr,$fw[name],($i+1),$fw[name],($i+1),$fw_name,$RudString);
                          $warningStr=sprintf("%s<div id='%s{R%d}' style='position:relative; visibility: visible'>",$warningStr,$fw[name],($i+1));
                          $warningStr=sprintf("%s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                          $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub>",$warningStr,$fw[name],($i+1),showRule($fw[rule][$i]));
                          foreach(explode(",",$RudString) as $CRud){
                            foreach(explode("R",$CRud) as $CRudIndex){
                              if($CRudIndex!=0){
                                $warningStr=sprintf("%s<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                                $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub>",$warningStr,$fw_name,$CRudIndex,showRule($fw_u[rule][($CRudIndex-1)]));
                              }
                            }
                          }
                          $warningStr=sprintf("%s</div>",$warningStr);
                          $nwarnings++;
                        }else{
                          //------------------------------------------------------
                          //CASE 3.1.4
                          echo "";
                          $debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=red><B> -> Partial Redundancy with %s{R%s}</B></font>",$debugStr,$fw_name,$RudString);
                          $warningStr=sprintf("%s<BR><a href=\"javascript:showWarning('%s{R%d}');\">%s{R%d}</a>:&nbsp;&nbsp;<font color=red><B> -> Partial Redundancy with %s{R%s}</B></font>",$warningStr,$fw[name],($i+1),$fw[name],($i+1),$fw_name,$RudString);
                          $warningStr=sprintf("%s<div id='%s{R%d}' style='position:relative; visibility: visible'>",$warningStr,$fw[name],($i+1));
                          $warningStr=sprintf("%s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                          $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub>",$warningStr,$fw[name],($i+1),showRule($fw[rule][$i]));
                          foreach(explode(",",$RudString) as $CRud){
                            foreach(explode("R",$CRud) as $CRudIndex){
                              if($CRudIndex!=0){
                                $warningStr=sprintf("%s<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                                $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub>",$warningStr,$fw_name,$CRudIndex,showRule($fw_u[rule][($CRudIndex-1)]));
                              }
                            }
                          }
                          $warningStr=sprintf("%s</div>",$warningStr);
                          $nwarnings++;
                        }//if_not_testRedundancy
                      }else{
                        //$debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=green><b> -> Case 3.1 for %s has been checked!</b></font>",$debugStr,$fw_name);
                      }//end_case_3.1

                      //
                      //CASE 3.1
                      //------------------------------------------------------


                    }elseif($fw[rule][$i][decision]=="accept"){

                      //------------------------------------------------------
                      //CASE 3.2
                      //
                      if($Rud[0]!=NULL){

                        $RudString=implode(",R",$anomaliesWithRud);
                        if(testRedundancy_inter($RudTestComplient,0)){
                          //------------------------------------------------------
                          //CASE 3.2.1
                          $debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=red><B> -> Full Shadowing with %s{R%s}</B></font>",$debugStr,$fw_name,$RudString);
                          $warningStr=sprintf("%s<BR><a href=\"javascript:showWarning('%s{R%d}');\">%s{R%d}</a>:&nbsp;&nbsp;<font color=red><B> -> Full Shadowing with %s{R%s}</B></font>",$warningStr,$fw[name],($i+1),$fw[name],($i+1),$fw_name,$RudString);
                          $warningStr=sprintf("%s<div id='%s{R%d}' style='position:relative; visibility: visible'>",$warningStr,$fw[name],($i+1));
                          $warningStr=sprintf("%s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                          $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub>",$warningStr,$fw[name],($i+1),showRule($fw[rule][$i]));
                          foreach(explode(",",$RudString) as $CRud){
                            foreach(explode("R",$CRud) as $CRudIndex){
                              if($CRudIndex!=0){
                                $warningStr=sprintf("%s<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                                $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub>",$warningStr,$fw_name,$CRudIndex,showRule($fw_u[rule][($CRudIndex-1)]));
                              }
                            }
                          }
                          $warningStr=sprintf("%s</div>",$warningStr);
                          $nwarnings++;
                        }else{
                          //------------------------------------------------------
                          //CASE 3.2.2
                          $debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=red><B> -> Partial Shadowing with %s{R%s}</B></font>",$debugStr,$fw_name,$RudString);
                          $warningStr=sprintf("%s<BR><a href=\"javascript:showWarning('%s{R%d}');\">%s{R%d}</a>:&nbsp;&nbsp;<font color=red><B> -> Partial Shadowing with %s{R%s}</B></font>",$warningStr,$fw[name],($i+1),$fw[name],($i+1),$fw_name,$RudString);
                          $warningStr=sprintf("%s<div id='%s{R%d}' style='position:relative; visibility: visible'>",$warningStr,$fw[name],($i+1));
                          $warningStr=sprintf("%s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                          $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub>",$warningStr,$fw[name],($i+1),showRule($fw[rule][$i]));
                          foreach(explode(",",$RudString) as $CRud){
                            foreach(explode("R",$CRud) as $CRudIndex){
                              if($CRudIndex!=0){
                                $warningStr=sprintf("%s<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                                $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub>",$warningStr,$fw_name,$CRudIndex,showRule($fw_u[rule][($CRudIndex-1)]));
                              }
                            }
                          }
                          $warningStr=sprintf("%s</div>",$warningStr);
                          $nwarnings++;
                        }
                      }elseif($fw_u[policy]=="close"){
                        if($Rua[0]==NULL){
                          //------------------------------------------------------
                          //CASE 3.2.3
                          $debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=red><B> -> Full Shadowing with %s{policy}</B></font>",$debugStr,$fw_name);
                          $warningStr=sprintf("%s<BR><a href=\"javascript:showWarning('%s{R%d}');\">%s{R%d}</a>:&nbsp;&nbsp;<font color=red><B> -> Full Shadowing with %s{policy}</B></font>",$warningStr,$fw[name],($i+1),$fw[name],($i+1),$fw_name);
                          $warningStr=sprintf("%s<div id='%s{R%d}' style='position:relative; visibility: visible'>",$warningStr,$fw[name],($i+1));
                          $warningStr=sprintf("%s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                          $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub></div>",$warningStr,$fw[name],($i+1),showRule($fw[rule][$i]));
                          $nwarnings++;
                        }elseif(!testRedundancy_inter($RuaTestComplient,0)){

                          $RuaString=implode(",R",$anomaliesWithRua);
                          //------------------------------------------------------
                          //CASE 3.2.4
                          $debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=red><B> -> Partial Shadowing with %s{R%s}</B></font>",$debugStr,$fw_name,$RuaString);
                          $warningStr=sprintf("%s<BR><a href=\"javascript:showWarning('%s{R%d}');\">%s{R%d}</a>:&nbsp;&nbsp;<font color=red><B> -> Partial Shadowing with %s{R%s}</B></font>",$warningStr,$fw[name],($i+1),$fw[name],($i+1),$fw_name,$RuaString);
                          $warningStr=sprintf("%s<div id='%s{R%d}' style='position:relative; visibility: visible'>",$warningStr,$fw[name],($i+1));
                          $warningStr=sprintf("%s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                          $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub>",$warningStr,$fw[name],($i+1),showRule($fw[rule][$i]));
                          foreach(explode(",",$RuaString) as $CRua){
                            foreach(explode("R",$CRua) as $CRuaIndex){
                              if($CRuaIndex!=0){
                                $warningStr=sprintf("%s<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                                $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub>",$warningStr,$fw_name,$CRuaIndex,showRule($fw_u[rule][($CRuaIndex-1)]));
                              }
                            }
                          }
                          $warningStr=sprintf("%s</div>",$warningStr);
                          $nwarnings++;
                        }else{
                          //$debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=green><b> -> Case 3.2 for %s has been checked!</b></font>",$debugStr,$fw_name);
                        }//end_case_3.2
                      }else{
                        //$debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=green><b> -> Case 3.2 for %s has been checked!</b></font>",$debugStr,$fw_name);
                      }//end_case_3.2
                    }//else_decision_is_deny
                    //
                    //CASE 3.2
                    //------------------------------------------------------
                    //}//foreach_path_u
                }else{
                  //$debugStr=sprintf("%s<BR> PATH_U is empty",$debugStr);
                  $emptyU=true;
                }

                //------------------------------------------------------
                //CASE 3.3
                //
                $path_d=getTail($p,$fw[name]);
                if(($path_d[0]!=NULL)&&($fw[rule][$i][decision]=="accept")){
                  //echo "<BR><font color=orange>$path_d[0]</font>";
                  $pathD=implode(",",$path_d);
                  $debugStr=sprintf("%s<BR>PATH_D={%s}",$debugStr,$pathD);
                  //foreach($path_d as $fw_name){
                    unset($fw_name);
                    $fw_name=$path_d[0];
                    //we check just the first path_d
                    $fw_d=getFirewall($fw_name,$data[components][fw]);
                    $Rda=obtainCorrelatedRules($fw_d,$fw[rule][$i],"accept");

                    if($Rda[0]!=NULL){
                      //$debugStr=sprintf("%s<BR><font color=green>Rda with %s is not empty!!!</font>",$debugStr,$fw_name);
                    }else{
                      //$debugStr=sprintf("%s<BR><font color=green>Rda with %s is empty!!!</font>",$debugStr,$fw_name);
                    }


                    if(($Rda[0]==NULL)&&($fw_d[policy]=="close")){
                      $debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=red><B> -> Full Misconnection with %s{policy}</B></font>",$debugStr,$fw_name);
                      $warningStr=sprintf("%s<BR><a href=\"javascript:showWarning('%s{R%d}');\">%s{R%d}</a>:&nbsp;&nbsp;<font color=red><B> -> Full Misconnection with %s{policy}</B></font>",$warningStr,$fw[name],($i+1),$fw[name],($i+1),$fw_name);
                      $warningStr=sprintf("%s<div id='%s{R%d}' style='position:relative; visibility: visible'>",$warningStr,$fw[name],($i+1));
                      $warningStr=sprintf("%s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                      $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub></div>",$warningStr,$fw[name],($i+1),showRule($fw[rule][$i]));
                      $nwarnings++;
                    }elseif($Rda[0]!=NULL){
                      $RdaTestComplient[0]=$fw[rule][$i];
                      $RdaCounter=1;
                      unset($anomaliesWithRda);
                      foreach($Rda as $rule){
                        $anomaliesWithRda[($RdaCounter-1)]=$rule[shadowing];
                        $RdaTestComplient[$RdaCounter]=$rule;
                        $RdaCounter++;
                      }
                      if((!testRedundancy_inter($RdaTestComplient,0))&&($fw_d[policy]=="close")){
                          $RdaString=implode(",R",$anomaliesWithRda);
                          $debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=red><B> -> Partial Misconnection with %s{R%s}</B></font>",$debugStr,$fw_name,$RdaString);
                          $warningStr=sprintf("%s<BR><a href=\"javascript:showWarning('%s{R%d}');\">%s{R%d}</a>:&nbsp;&nbsp;<font color=red><B> -> Partial Misconnection with %s{R%s}</B></font>",$warningStr,$fw[name],($i+1),$fw[name],($i+1),$fw_name,$RdaString);
                          $warningStr=sprintf("%s<div id='%s{R%d}' style='position:relative; visibility: visible'>",$warningStr,$fw[name],($i+1));
                          $warningStr=sprintf("%s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                          $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub>",$warningStr,$fw[name],($i+1),showRule($fw[rule][$i]));
                          foreach(explode(",",$RdaString) as $CRda){
                            foreach(explode("R",$CRda) as $CRdaIndex){
                              if($CRdaIndex!=0){
                                $warningStr=sprintf("%s<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$warningStr);
                                $warningStr=sprintf("%s<sub>%s{R%d}:%s</sub>",$warningStr,$fw_name,$CRdaIndex,showRule($fw_d[rule][($CRdaIndex-1)]));
                              }
                            }
                          }
                          $warningStr=sprintf("%s</div>",$warningStr);
                          $nwarnings++;
                      }else{
                        //$debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=green><b> -> Case 3.3 for %s has been checked!</b></font>",$debugStr,$fw_name);
                      }
                    }elseif($Rda[0]==NULL){
                      //$debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=green><b> -> Case 3.3 for %s has been checked!</b></font>",$debugStr,$fw_name);
                    }//else
                    //}//foreach_path_d
                }elseif($path_d[0]==NULL){
                  //$debugStr=sprintf("%s<BR> PATH_D is empty",$debugStr);
                  $emptyD=true;
                }else{
                  $pathD=implode(",",$path_d);
                  $debugStr=sprintf("%s<BR>PATH_D={%s}",$debugStr,$pathD);
                  //$debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=green><b> -> Case 3.3 for %s has been checked!</b></font>",$debugStr,$fw_name);
                }
                //
                //CASE 3.3
                //------------------------------------------------------
              }//elseif_inside($fw[name],$p)
              if($emptyD and $emptyU){
                $debugStr=sprintf("%s<BR>&nbsp;&nbsp;<font color=green><b> -> Both PATH_U and PATH_D are empty ... no more actions should be done!</b></font>",$debugStr);
              }
            }else{
              $debugStr=sprintf("%s&nbsp;&nbsp;&nbsp;<b>Path $p is empty!!</b>",$debugStr);
            }
            $debugStr=sprintf("%s<BR>",$debugStr);
          }//elseif(Z1!=Z2)
        }//for_each_zd
      }//foreach_Zs
      $debugStr=sprintf("%s<BR>",$debugStr);
    }//foreach_rule
    $debugStr=sprintf("%s<BR>",$debugStr);
  }//foreach_fw

  if($view=="all"){
    echo $debugStr;
  }else{
    if($nwarnings>0){
      if($nwarnings==1){
        printf("<script languaje=\"javascript\">window.alert(\"%s%s\");</script><BR>",$nwarnings," anomaly has been found");
        echo "<b>/* $nwarnings anomaly has been found */</b><BR>";
      }else{
        printf("<script languaje=\"javascript\">window.alert(\"%s%s\");</script><BR>",$nwarnings," anomalies have been found");
        echo "<b>/* $nwarnings anomalies have been found */</b><BR>";
      }
      echo $warningStr;
      echo "<BR>";
    }else{
      printf("<script languaje=\"javascript\">window.alert(\"%s\");</script><BR>","No anomalies have been found");
      echo "<b>/* No anomalies have been found */</b><BR>";
    }
  }

  $end = my_microtime();
  printf("<BR><b> /* Whole process done in %f seconds. */</b><BR>",round($end-$start,5));

}//(4)detection-inter-component([...])
//---------------------- Main Functions -------------------------------------------


//----------------------- INTRA-Components functions -----------------------------
//-------------------------------------------------
//testRedundancy([...])
function testRedundancy($R,$i){
  $test=false;
  if($R[$i][shadowing]!="true"){
    $j=($i+1);
    $temp=$R[$i];
    $temp[exluded_by]=Null;
    while ($test==false and $j<=count($R)){
      if ($temp[decision] == $R[$j][decision]){
        $temp=exclusion($temp,$R[$j],$j,$j);
        if(emptyCondition($temp)){
          $test=$temp[excluded_by];
        }//if
      }
      $j++;
    }
  }//if
  return $test;
}
//testRedundancy([...])
//-------------------------------------------------


//-------------------------------------------------
//attr_disjoint
function attr_disjoint($B,$A,$p){
  $result=false;
  $l=0;//current attribute
  while((!$result)&&($l<$p)){
    $Brange=explode(",",$B[$l][range]);
    $Arange=explode(",",$A[$l][range]);
    $intersect=my_intersect($Arange,$Brange);
    if($intersect[0]==-1){
      $result=true;
    }//if
    $l++;
  }//while
  return $result;
}
//attr_disjoint
//-----------------------------------------------

//-----------------------------------------------
//get_elements
function get_elements($Bcondition,$Acondition,$p){
  $r=0;
  for($i=0;$i<$p;$i++){
    $e=0;
    //------------------------------------------------
    //diagonal element
    $Arange=explode(",",$Acondition[$i][range]);
    $Brange=explode(",",$Bcondition[$i][range]);
    $diff=my_diff($Brange,$Arange);
    if($diff[0]==-1){
      $Caux= array($Bcondition[$i][name] => "0,0");
      $Ccondition[$r][$i]=$Caux;
      $e++;
    }else{
      $Ccondition[$r+$e][$i]= array($Bcondition[$i][name] => "$diff[0],$diff[1]");
      $e++;
      if(count($diff)>2){
        $Ccondition[$r+$e][$i]= array($Bcondition[$i][name] => "$diff[2],$diff[3]");
        $e++;
      }//if
    }//else
    //------------------------------------------------
    //prefix
    for($j=0;$j<$i;$j++){
      $Arange=explode(",",$Acondition[$j][range]);
      $Brange=explode(",",$Bcondition[$j][range]);
      $intersect=my_intersect($Brange,$Arange);
      if($intersect[0]==-1){
        $Caux= array($Bcondition[$j][name] => "0,0");
      }else{
        $Caux= array($Bcondition[$j][name] => "$intersect[0],$intersect[1]");
      }
      for($ee=0;$ee<$e;$ee++){
        $Ccondition[$r+$ee][$j]=$Caux;
      }
    }
    //------------------------------------------------
    //suffix
    for($z=$i+1;$z < count($Bcondition);$z++){
      $Caux= array($Bcondition[$z][name] => $Bcondition[$z][range]);
      for($ee=0;$ee<$e;$ee++){
        $Ccondition[$r+$ee][$z]=$Caux;
      }//for
    }//for
    //------------------------------------------------
    $r=$r+$e;
  }//for(i to p)
  return $Ccondition;
}
//get_elements
//-----------------------------------------------

//-----------------------------------------------
//exclusion([...])
function exclusion($B,$A,$step,$rule){

  if(($B[shadowing]=="true")||($B[redundancy]=="true")){
    return $B;
  }

  if(isset($B[excluded_by])){
    $excluded_by=sprintf("%s",$B[excluded_by]);
  }else{
    $excluded_by=Null;
  }

  $C= array('condition' => Null,
            'decision' => $B[decision],
            'excluded_by' => $excluded_by,
            'nids_misc' => $B[nids_misc],
            'shadowing' => "false",
            'redundancy' => "false");

  for($i=0;$i<count($A[condition][subcondition]);$i++){
    $j=0;
    foreach($A[condition][subcondition][$i] as $Akey => $Avalue){
      $Acondition[$i][$j]= array('name' => $Akey,
                                 'range' => $Avalue);
      $j++;
    }
  }
  for($i=0;$i<count($B[condition][subcondition]);$i++){
    $j=0;
    foreach($B[condition][subcondition][$i] as $Bkey => $Bvalue){
      $Bcondition[$i][$j]= array('name' => $Bkey,
                                 'range' => $Bvalue);
      $j++;
    }
  }

  //number of condition attributes
  $p=count($Acondition[0]);

  //$c will be the number of subconditions of rule C.
  $c=0;

  //to check at the end ...
  $modified=false;
  //for all the subconditions of rule B
  for($j=0;$j<count($Bcondition);$j++){
    //for all the subconditions of rule A
    for($i=0;$i<count($Acondition);$i++){
      //if the intersection of all the attributes is not empty
      if(!attr_disjoint($Bcondition[$j],$Acondition[$i],$p)){
        $Ccondition=get_elements($Bcondition[$j],$Acondition[$i],$p);
        foreach($Ccondition as $CC){
          $empty=false;
          foreach($CC as $Cpair){
            foreach($Cpair as $Ckey => $Cvalue){
              if(($Cvalue==",")||($Cvalue=="0,0")){
                $empty=true;
              }//if
              $Aux[$Ckey]=$Cvalue;
            }//foreach
          }//foreach
          if(!$empty){
            $C[condition][subcondition][$c]=$Aux;
            $c++;
          }//if
        }//foreach
        //the subcondition has been modified
        $modified=true;
      }//if_attr_disjoint
    }//for_i

    //if the current subcondition has not been modified,
    //we replace it with the original one from rule B.
    if(!$modified){
      $C[condition][subcondition][$c]=$B[condition][subcondition][$j];
      $c++;
    }else{
      if($C[excluded_by]!=Null){
        $C[excluded_by]=sprintf("%s,R%d",$C[excluded_by],$step+1);
      }else{
        $C[excluded_by]=sprintf("R%d",$step+1);
      }
    }
  }//for_j

  //the last subcondition must be always null, as a mark of end.
  $C[condition][subcondition][$c]=Null;

  return $C;
}//exclusion([...])


//showTable([...])
function showTable($data){

  $rulestabular="<table border=2 width=\"100\%\"><tr align=\"center\">"
    ."<td><b>Order</b><td><b>Protocol</b></td>"
    ."<td><b>srcAddr</b></td><td><b>srcPort</b></td>"
    ."<td><b>destAddr</b></td><td><b>destPort</b></td>"
    ."<td><b>Action</b></td>"
    ."</tr>";

  for($i=0;$i<count($data[rule]);$i++){
    $rulestabular .= "<tr align=\"center\">";
    $action=$data[rule][$i][decision];
    for($j=0;$j<(count($data[rule][$i][condition][subcondition]));$j++){
        if($j<count($data[rule][$i][condition][subcondition])-1){
          $rulestabular .= "<tr align=\"center\">";
          $subrule=$data[rule][$i][condition][subcondition][$j];
          if(count($data[rule][$i][condition][subcondition])==2){
            $rulestabular .= "<td>".($i+1)."</td>";
          }else{
            $rulestabular .= "<td>".($i+1).",".($j+1)."</td>";
          }
          //protocol
          if($subrule[p]=="1,1"){
            $rulestabular .= "<td>tcp</td>";
          }elseif($subrule[p]=="2,2"){
            $rulestabular .= "<td>udp</td>";
          }elseif($subrule[p]=="1,2"){
            $rulestabular .= "<td>any</td>";
          }else{
            $rulestabular .= "<td>icmp</td>";
          }
          //sourceAddr
          $rulestabular .= "<td>&nbsp;".$subrule[s]."</td>";
          //sourcePort
          if($subrule[sP]=="1,65535"){
            $rulestabular .= "<td>any</td>";
          }else{
            $rulestabular .= "<td>&nbsp;".$subrule[sP]."</td>";
          }

          //destAddr
          $rulestabular .= "<td>&nbsp;".$subrule[d]."</td>";

          //destPort
          if($subrule[dP]=="1,65535"){
            $rulestabular .= "<td>any</td>";
          }else{
            $rulestabular .= "<td>&nbsp;".$subrule[dP]."</td>";
          }

          //action
          if($data[type]=="NIDS"){
            if($action=="accept"){
              $rulestabular .= "<td>pass</td>";
            }elseif($action=="deny"){
              $rulestabular .= "<td>alert</td>";
            }
          }else{
            //$rulestabular .= "<td>".$action."</td>";
            $rulestabular .= "<td>".$action."</td>";
          }

          //close_table
          $rulestabular .= "</tr>";
        }
    }
  }//for

  //default
  if($data[type]=="NIDS"){
    if($data[policy]=="open"){
      $action="pass";
    }elseif($data[policy]=="close"){
      $action="alert";
    }
  }else{
    if($data[policy]=="open"){
      $action="accept";
    }elseif($data[policy]=="close"){
      $action="deny";
    }
  }


  $rulestabular .= "<tr align=\"center\">";
  $rulestabular .= "<td>".($i+1)."</td>";
  //protocol
  $rulestabular .= "<td>any</td>";
  //sourceAddr
  $rulestabular .= "<td>any</td>";
  //sourcePort
  $rulestabular .= "<td>any</td>";
  //destAddr
  $rulestabular .= "<td>any</td>";
  //destPort
  $rulestabular .= "<td>any</td>";
  //action
  $rulestabular .= "<td>".$action."</td>";
  //close table
  $rulestabular .= "</tr>";
  $rulestabular .= "</table>";

  echo "$rulestabular";

}//showTable([...])

//showData([...])
function showData($data){
  $nRules=0;
  $nRounds=0;
  for($i=0;$i<count($data[rule]);$i++){
    $R=$data[rule][$i];
    $fancyPosition=$i+1;
    echo "<BR>R$fancyPosition:&nbsp;";

    //show conditions
    if(count($R[condition][subcondition])==1){
      //echo "<font size=3>&empty;</font>";
      echo "<i>0</i>";
    }else{
      $subconditions=(count($R[condition][subcondition])>2);
      if($subconditions){
        echo "{";

      }//if
      $nsubRules=0;
      $nConditions=0;
      $nRounds=0;
      for($offset=0;$offset<(count($R[condition][subcondition])-1);$offset++){
        $condition=$R[condition][subcondition][$offset];
        $j=0;
        $nRules++;
        $nConditions++;
        $nRounds++;
        foreach($condition as $key => $value){
          if(($subconditions)&&($nRounds==1)){
            echo "<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
            $nRounds=0;
          }
          if($j!=0){
            //echo "<font size=.1>&and;</font>&nbsp;";
            echo ",";
          }
          if(($value=="0,0")||($value==",")){
            //echo "<font size=3>&empty;</font>";
            echo "<i>0</i>";
          }else{
            //echo $key." <font size=1>&isin;</font> [".$value."] ";
            echo "[".$value."]";
          }
          $j++;
        }//foreach
        if($offset<(count($R[condition][subcondition])-2)){
          //echo "&nbsp;,&nbsp;";
        }//if
      }//for
      if($subconditions){
        echo "<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}";
      }//if
    }//else
    //echo "&nbsp;&rarr;&nbsp;$R[decision]";
    echo "&nbsp;-->&nbsp;$R[decision]";
    if($nConditions>1){
      echo "&nbsp;&nbsp;<i>($nConditions subconditions)</i><BR>";
    }
    //excluded_by
    if(isset($R[excluded_by])){
      echo "&nbsp;(exc_by: $R[excluded_by])";
    }
  }//for
  //echo "<BR><BR>Number of rules == $nRules";
}//showData([...])


//showResults([...])
function showResults($data){
  $nRules=0;
  $nRounds=0;
  for($i=0;$i<count($data[rule]);$i++){
    $R=$data[rule][$i];
    $fancyPosition=$i+1;
    if(($R[shadowing]!="true")&&($R[redundancy]!="true")){
      echo "<BR>R$fancyPosition:&nbsp;";

      //show conditions
      if(count($R[condition][subcondition])==1){
        //echo "<font size=3>&empty;</font>";
        echo "<i>0</i>";
      }else{
        $subconditions=(count($R[condition][subcondition])>2);
        if($subconditions){
          echo "{";

        }//if
        $nsubRules=0;
        $nConditions=0;
        $nRounds=0;
        for($offset=0;$offset<(count($R[condition][subcondition])-1);$offset++){
          $condition=$R[condition][subcondition][$offset];
          $j=0;
          $nRules++;
          $nConditions++;
          $nRounds++;
          foreach($condition as $key => $value){
            if(($subconditions)&&($nRounds==1)){
              echo "<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
              $nRounds=0;
            }
            if($j!=0){
              //echo "<font size=.1>&and;</font>&nbsp;";
              echo ",";
            }
            if(($value=="0,0")||($value==",")){
              //echo "<font size=3>&empty;</font>";
              echo "<i>0</i>";
            }else{
              //echo $key." <font size=1>&isin;</font> [".$value."] ";
              echo "[".$value."]";
            }
            $j++;
          }//foreach
          if($offset<(count($R[condition][subcondition])-2)){
            //echo "&nbsp;,&nbsp;";
          }//if
        }//for
        if($subconditions){
          echo "<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}";
        }//if
      }//else
      //echo "&nbsp;&rarr;&nbsp;$R[decision]";
      echo "&nbsp;-->&nbsp;$R[decision]";
      if($nConditions>1){
        echo "&nbsp;&nbsp;<i>($nConditions subconditions)</i><BR>";
      }
    }//if
  }//for
  //echo "<BR><BR>Number of rules == $nRules";
}//showResults([...])


//showWarnings([...])
function showWarnings($data){
  $nwarnings=0;
  $shown=false;
  for($i=0;$i<count($data[rule]);$i++){
    $R=$data[rule][$i];
    $fancyPosition=$i+1;
    if ($R[shadowing]=="true"||$R[redundancy]=="true"){
      $nwarnings++;
      if(!$shown){
        echo "<font color=black><b>/* warnings */</b></font><BR>";
        $shown=true;
      }
      if ($R[shadowing]=="true"){
        unset($excluded_by);
        $excluded_by=implode(",",array_unique(explode(",",$data[rule][$i][excluded_by])));
        //echo "<BR><b><font color=\"red\">R<sub>$fancyPosition</sub>[shadowing]=true</font></b>";
        echo "<BR><b><font color=\"red\">R<sub>$fancyPosition</sub> is shadowed by ".$excluded_by."</font></b>";
      }
      if ($R[redundancy]=="true"){
        unset($excluded_by);
        $excluded_by=implode(",",array_unique(explode(",",$data[rule][$i][excluded_by])));
        //echo "<BR><b><font color=\"red\">R<sub>$fancyPosition</sub>[redundancy]=true</font></b>";
        echo "<BR><b><font color=\"red\">R<sub>$fancyPosition</sub> is redundant to ".$excluded_by."</font></b>";
      }
    }
  }//for
  return $nwarnings;
}//showWarnings([...])

//emptyCondition([...])
function emptyCondition($C){
  $empty=true;
  $i=0;
  while($empty&&($i<(count($C[condition][subcondition])-1))){
    $condition=$C[condition][subcondition][$i];
    foreach($condition as $key => $value){
      if(($value!="0,0")&&($value!=",")){
        $empty=false;
      }//if
    }//foreach
    $i++;
  }//while
  return $empty;
}//emptyCondition([...])

//is_IPv4()
function is_IPv4($A){
  if (ereg("([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)",$A,$regs)) {
    return true;
  }else{
    return false;
  }
}//is_IPv4()

//my_diff()
function my_diff($B,$A){
  $C[0]=-1;

  if(($A[0]>$B[1])||($B[0]>$A[1])){
      $C[0]=$B[0];
      $C[1]=$B[1];
  }elseif($A[0]>$B[0]){
      $C[0]=$B[0];
      $C[1]=$A[0]-1;
      if($B[1]>$A[1]){
        $C[2]=$A[1]+1;
        $C[3]=$B[1];
      }
  }elseif($B[1]>$A[1]){
      $C[0]=$A[1]+1;
      $C[1]=$B[1];
  }
  return $C;
}//my_diff()

//my_intersect()
function my_intersect($B,$A){
  $C[0]=-1;
  if($A[0]<=$B[0]){
    if($A[1]>=$B[1]){
      $C[0]=$B[0];
      $C[1]=$B[1];
    }elseif($A[1]>=$B[0]){
      $C[0]=$B[0];
      $C[1]=$A[1];
    }
  }else{
    if ($A[1]<=$B[1]){
      $C[0]=$A[0];
      $C[1]=$A[1];
    }elseif($A[0]<=$B[1]){
      $C[0]=$A[0];
      $C[1]=$B[1];
    }
  }
  return $C;
}//my_intersect()

//my_microtime()
function my_microtime(){
  list($usec, $sec) = explode(' ', microtime());
  return ((float)$usec + (float)$sec);
}//my_microtime()
//----------------------- INTRA-Components functions -----------------------------

//---------------------- INTER-Components functions -------------------------------------------
//obtainCorrelatedRules([...])
function obtainCorrelatedRules($fw_d,$r,$decision){
  $i=0;$order=1;
  $RdC[0]=NULL;
  foreach($fw_d[rule] as $rd){
    if($rd[decision]==$decision){
      $C=exclusion($r,$rd,1,1);
      if(!sameRule($C,$r)){
        $RdC[$i]=$rd;
        $RdC[$i][shadowing]=$order;
        $i++;
      }//if_not_same_rule
    }//if_decision_is_accept
    $order++;
  }//foreach
  return $RdC;
}//obtainCorrelatedRules([...])

//function getFirewall([...])
function getFirewall($fw_name,$firewalls) {
  $FW=NULL;
  $i=0;
  while(($i<count($firewalls))&&($FW==NULL)){
    if($firewalls[$i][name]==$fw_name){
      $FW=$firewalls[$i];
    }
    $i++;
  }//while
  return $FW;
}//function getFirewall([...])

//getHeader([...])
function getHeader($p,$fwName){
  $path=explode(',',$p);
  $header[0]=NULL;
  $i=0;
  while(($i<=count($path))&&($path[$i]!=$fwName)){
    $header[$i]=$path[$i];
    $i++;
  }

  return $header;
}
//getHeader([...])

//getTail([...])
function getTail($p,$fwName){
  $path=explode(',',$p);
  $tail[0]=NULL;
  $i=0;$j=0;

  while(($i<count($path))&&($path[$i]!=$fwName)){
    $i++;
  }

  if($path[$i]==$fwName){
    $i++;
    while($path[$i]!=NULL){
      $tail[$j]=$path[$i];
      $i++;$j++;
    }
  }

  return $tail;

}
//getTail([...])

//inside([...])
function inside($fwname,$p){
  $inside=false;
  $firewalls=explode(',',$p);
  $i=0;
  while(($i<count($firewalls))&&(!$inside)){
    $inside=($firewalls[$i]==$fwname);
    $i++;
  }
  return $inside;
}
//inside([...])

//getPaths([...])
function getPaths($mr,$Z1,$Z2){
  $P=NULL;
  $i=0;
  while(($i<count($mr))&&($P==NULL)){
    $zone=explode(',',$mr[$i][zone]);
    if($zone[0]==$Z1){
      if($zone[1]==$Z2){
        $P=$mr[$i][content];
      }
    }elseif($zone[0]==$Z2){
      if($zone[1]==$Z1){
        $RP=explode(",",$mr[$i][content]);
        $P=implode(",",array_reverse($RP));
      }
    }
    $i++;
  }
  return $P;
}
//getPaths([...])

//is_inside[...]
function is_inside($source,$rangeInclusion,$rangeExclusion){

  $included=false;
  $srcIP=explode(",",$source);
  $inclusion=explode(",",$rangeInclusion);
  $exclusion=explode(",",$rangeExclusion);

  if($rangeInclusion=="FF:FF:FF:FF:FF:FF/0"){
    return false;
  }

  $i=0;
  while((!$included)&&($i<count($inclusion))){
    if(Ip2SubsetEqIp1($inclusion[$i],$srcIP[0]) or
       Ip2SubsetEqIp1($inclusion[$i],$srcIP[1])){
      $included=true;
    }else{
      $i++;
    }
  }

  if($included){

    $included=false;
    $i=0;
    while((!$included)&&($i<count($inclusion))){
      if(Ip2SubsetEqIp1($inclusion[$i],$srcIP[1])){
        $included=true;
      }else{
        $i++;
      }
    }

    if($included){
      $i=0;
      while(($included)&&($i<count($exclusion))){
        if(Ip2SubsetEqIp1($exclusion[$i],$srcIP[0])){
          $included=false;
        }else{
          $i++;
        }
      }//while

      if($included){
        $i=0;
        while(($included)&&($i<count($exclusion))){
          if(Ip2SubsetEqIp1($exclusion[$i],$srcIP[1])){
            $included=false;
          }else{
            $i++;
          }
        }
      }//if_3

    }//if_2

  }//if_1

  return $included;

}


//obtainZs[...]
function obtainZs($zones,$R){

  $Zs=Null;

  for($offset=0;$offset<(count($R[condition][subcondition])-1);$offset++){
    $ss=explode(',',$R[condition][subcondition][$offset][s]);
    $source=sprintf("%s,%s",long2ip($ss[0]),long2ip($ss[1]));
    //    $source=$R[condition][subcondition][$offset][s];
    $i=0;
    foreach($zones[zone] as $zone){
      if(is_inside($source,$zone[included],$zone[excluded])){
        $Zs[$i]=$zone[name];
        $i++;
      }//if
    }//foreach

  }//for

  if($Zs!=Null){
    return array_unique($Zs);
  }else{
    return Null;
  }

}//obtainZs[...]

//obtainZd[...]
function obtainZd($zones,$R){

  $Zd=Null;

  for($offset=0;$offset<(count($R[condition][subcondition])-1);$offset++){
    $dd=explode(',',$R[condition][subcondition][$offset][d]);
    $destination=sprintf("%s,%s",long2ip($dd[0]),long2ip($dd[1]));
    //    $destination=$R[condition][subcondition][$offset][d];
    $i=0;
    foreach($zones[zone] as $zone){
      if(is_inside($destination,$zone[included],$zone[excluded])){
        $Zd[$i]=$zone[name];
        $i++;
      }//if
    }//foreach

  }//for

  if($Zd!=Null){
    return array_unique($Zd);
  }else{
    return Null;
  }

}//obtainZd[...]

//-------------------------------------------------
//testRedundancy_inter([...])
function testRedundancy_inter($R,$i){
  $test=false;
  if($R[$i][shadowing]!="true"){
    $j=($i+1);
    $temp=$R[$i];
    while (!$test and $j<count($R)){
      //if ($temp[decision] == $R[$j][decision]){
        $temp=exclusion($temp,$R[$j],$i,$j);
        if(emptyCondition($temp)){
          $test=true;
        }//if
        // }
      $j++;
    }
  }//if
  return $test;
}
//testRedundancy_inter([...])
//-------------------------------------------------

//showData_inter([...])
function showData_inter($data){
  $debugStr="";
  $nRules=0;
  $nRounds=0;
  for($i=0;$i<count($data[rule]);$i++){
    $R=$data[rule][$i];
    $fancyPosition=$i+1;
    $debugStr=sprintf("%s<BR>R%s:&nbsp;",$debugStr,$fancyPosition);

    //show conditions
    if(count($R[condition][subcondition])==1){
      $debugStr=sprintf("%s<i>0</i>",$debugStr);
    }else{
      $subconditions=(count($R[condition][subcondition])>2);
      if($subconditions){
        $debugStr=sprintf("%s{",$debugStr);
      }//if
      $nsubRules=0;
      $nConditions=0;
      $nRounds=0;
      for($offset=0;$offset<(count($R[condition][subcondition])-1);$offset++){
        $condition=$R[condition][subcondition][$offset];
        $j=0;
        $nRules++;
        $nConditions++;
        $nRounds++;
        foreach($condition as $key => $value){
          if(($subconditions)&&($nRounds==1)){
            $debugStr=sprintf("%s<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$debugStr);
            $nRounds=0;
          }
          if($j!=0){
            $debugStr=sprintf("%s,",$debugStr);
          }
          if(($value=="0,0")||($value==",")){
            $debugStr=sprintf("%s<i>0</i>",$debugStr);
          }else{
            if(($key=="s")||($key=="d")){
              $vv=explode(',',$value);
              $debugStr=sprintf("%s[%s,%s]",$debugStr,long2ip($vv[0]),long2ip($vv[1]));
            }else{
              $debugStr=sprintf("%s[%s]",$debugStr,$value);
            }
          }
          $j++;
        }//foreach
        if($offset<(count($R[condition][subcondition])-2)){
          //echo "&nbsp;,&nbsp;";
        }//if
      }//for
      if($subconditions){
        $debugStr=sprintf("%s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}",$debugStr);
      }//if
    }//else
    //echo "&nbsp;&rarr;&nbsp;$R[decision]";
      $debugStr=sprintf("%s&nbsp;-->&nbsp;%s",$debugStr,$R[decision]);
      if($nConditions>1){
        $debugStr=sprintf("%s&nbsp;&nbsp;<i>(%s subconditions)</i><BR>",$debugStr,$nConditions);
      }
    }//for
    //echo "<BR><BR>Number of rules = $nRules";
    return $debugStr;

}//showData_inter([...])

//showRule([...])
function showRule($R){

  $debugStr="";

    //show conditions
    if(count($R[condition][subcondition])==1){
      //echo "<font size=3>&empty;</font>";
      $debugStr=sprintf("%s<i>0</i>",$debugStr);
    }else{
      $subconditions=(count($R[condition][subcondition])>2);
      if($subconditions){
        $debugStr=sprintf("%s{",$debugStr);
      }//if
      $nsubRules=0;
      $nConditions=0;
      $nRounds=0;
      for($offset=0;$offset<(count($R[condition][subcondition])-1);$offset++){
        $condition=$R[condition][subcondition][$offset];
        $j=0;
        $nRules++;
        $nConditions++;
        $nRounds++;
        foreach($condition as $key => $value){
          if(($subconditions)&&($nRounds==1)){
            $debugStr=sprintf("%s<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;",$debugStr);
            $nRounds=0;
          }
          if($j!=0){
            //echo "<font size=.1>&and;</font>&nbsp;";
            $debugStr=sprintf("%s,",$debugStr);
          }
          if(($value=="0,0")||($value==",")){
            //echo "<font size=3>&empty;</font>";
            $debugStr=sprintf("%s<i>0</i>",$debugStr);
          }else{
            //echo $key." <font size=1>&isin;</font> [".$value."] ";
            if($key=="s"){
              $debugStr=sprintf("%s from ",$debugStr);
              $vv=explode(',',$value);
              $debugStr=sprintf("%s[%s,%s]",$debugStr,long2ip($vv[0]),long2ip($vv[1]));
            }elseif($key=="d"){
              $debugStr=sprintf("%s to ",$debugStr);
              $vv=explode(',',$value);
              $debugStr=sprintf("%s[%s,%s]",$debugStr,long2ip($vv[0]),long2ip($vv[1]));
            }
            // else{
//               $debugStr=sprintf("%s[%s]",$debugStr,$value);
//             }
          }
          $j++;
        }//foreach
        if($offset<(count($R[condition][subcondition])-2)){
          //echo "&nbsp;,&nbsp;";
        }//if
      }//for
      if($subconditions){
        $debugStr=sprintf("%s<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}",$debugStr,$value);
      }//if
    }//else
    //echo "&nbsp;&rarr;&nbsp;$R[decision]";
    $debugStr=sprintf("%s&nbsp;-->&nbsp;%s",$debugStr,$R[decision]);

    return $debugStr;
}//showRule([...])


//sameRule([...])
function sameRule($C,$R){
  $same=false;
  //if($C[decision]==$R[decision]){
    if(count($C[condition][subcondition])==count($R[condition][subcondition])){
      $same=true;
      $i=0;
      while($same&&($i<(count($C[condition][subcondition])-1))){
        if(count($C[condition][subcondition][$i])==count($R[condition][subcondition][$i])){
          $condition=$C[condition][subcondition][$i];
          foreach($condition as $key => $value){
            if(($value!=$R[condition][subcondition][$i][$key])){
              $same=false;
            }//if_same_attribute_value
          }//foreach
        }else{
          $same=false;
        }//if_same_number_attributes
        $i++;
      }//while
    }//if_same_number_subconditions
    //  }//if_same_decision

  return $same;
}//sameRule([...])
//---------------------- INTER-Components functions -------------------------------------------


//---------------------- IPv4 functions -------------------------------------------
function cidr2range($net){
  $start=strtok($net,"/");
  $n=3-substr_count($net, ".");
  if ($n>0){
    for ($i=$n;$i>0;$i--){
      $start.=".0";
    }
  }
  $bits1=str_pad(decbin(ip2long($start)),32,"0","STR_PAD_LEFT");
  $net=pow(2,(32-substr(strstr($net,"/"),1)))-1;
  $bits2=str_pad(decbin($net),32,"0","STR_PAD_LEFT");
  for($i=0;$i<32;$i++){
    if ($bits1[$i]==$bits2[$i]){
      $final.=$bits1[$i];
    }
    if(($bits1[$i]==1) and ($bits2[$i]==0)){
      $final.=$bits1[$i];
    }
    if(($bits1[$i]==0) and ($bits2[$i]==1)){
      $final.=$bits2[$i];
    }
  }
  return $start.",".long2ip(bindec($final));
}

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

function Ip2SubsetEqIp1($range,$ip) {
  $result = 1;

  if($range==$ip){
    return 1;

  }else{
    if (ereg("([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/([0-9]+)",$range,$regs)) {

      //perform a mask match
      $ipl = ip2long($ip);
      $rangel = ip2long($regs[1] . "." . $regs[2] . "." . $regs[3] . "." . $regs[4]);

      $maskl = 0;

      for ($i = 0; $i< 31; $i++) {
        if ($i < $regs[5]-1) {
          $maskl = $maskl + pow(2,(30-$i));
        }
      }

      if (($maskl & $rangel) == ($maskl & $ipl)) {
        return 1;
      } else {
        return 0;
      }
    } else {

      //range based
      $maskocts = split("\.",$range);
      $ipocts = split("\.",$ip);

      //perform a range match
      for ($i=0; $i<4; $i++) {
        if (ereg("\[([0-9]+)\-([0-9]+)\]",$maskocts[$i],$regs)) {
          if ( ($ipocts[$i] > $regs[2]) || ($ipocts[$i] < $regs[1])) {
            $result = 0;
          }
        }else{
            if ($maskocts[$i] <> $ipocts[$i]) {
              $result = 0;
            }
        }
      }
    }
    return $result;
  }//else
}//Ip2SubsetEqIp1

//within[...]
function within($source,$rangeInclusion,$rangeExclusion){

  $included=false;
  $inclusion=explode(",",$rangeInclusion);
  $exclusion=explode(",",$rangeExclusion);

  if($rangeInclusion=="0.0.0.0/0"){
    return false;
  }

  $i=0;
  while((!$included)&&($i<count($inclusion))){
    if(Ip2SubsetEqIp1($inclusion[$i],$source)){
      $included=true;
    }else{
      $i++;
    }
  }

  if($included){
    $i=0;
    while(($included)&&($i<count($exclusion))){
      if(Ip2SubsetEqIp1($exclusion[$i],$source)){
        $included=false;
      }else{
        $i++;
      }
    }//while
  }

  return $included;
}
//---------------------- IPv4 functions -------------------------------------------

//---------------------- graph class -------------------------------------------
// Based on the PHP class of Dragos Protung licensed under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation;
// Cf.
//    	http://www.phpclasses.org/browse/file/6514.html
// 	http://www.phpclasses.org/browse/author/113683.html

class graph{
  function graph($matrix){
    $this -> m     = $matrix;
    $this -> n     = count($this -> m);
    $this -> varf  = 0;
    $this -> s     = array();
    $this -> nod   = null;
    $this -> end   = null;
    $this -> routes = array();
  }
  function verify($c) {
    for ($i=0; $i<$this -> varf; $i++)
      if ($this -> s[$i]==($c)) return true;
    return false;
  }
  function ret_all($y) {
    (int)$y;
    if($this -> varf==1){
      return;
    }
    for ($i=0; $i<$this -> varf ; $i++) {
      $this -> routes[$y] = array_merge($this -> routes[$y], $this -> s[$i]);
    }
    $dist =0;
    for ($i=0; $i<$this -> varf-1 ; $i++) {
      $dist += $this -> m[$this -> s[$i]][$this -> s[$i+1]];
    }
    $sum = array("dist" => $dist);
    $this -> routes[$y] = array_merge($this -> routes[$y], $sum);
  }
  function paths_from_point($nod) {
    $this -> routes = array();
    (int)$this -> nod = $nod;
    $this -> s[$this -> varf] = $this -> nod;
    $this -> varf++;
    $rand = $this -> nod;
    $col = 0;
    $parcurs = 0;
    $x = 0;
    while ($parcurs == 0) {
      while (($this -> m[$rand][$col]==0) && ($col<$this -> n)){
        $col++;
      }
      if ($col<$this -> n) {
        if (!graph::verify($col)) {
          $this -> s[$this -> varf] = $col;
          $this -> varf++;
          $rand = $col;
          $col = 0;
        }
        else $col++;
      }
      else {
        graph::ret_all($x);
        $x++;
        $extrag = $this -> s[($this -> varf-1)];
        $this -> varf--;
        if ($extrag == $this -> nod){
          $parcurs = 1;
        }
        else {
          $col  = ($extrag+1);
          $rand = $this -> s[($this -> varf-1)];
        }
      }
    }
  }
  function paths_from_point_to_point($nod, $end) {
    graph::paths_from_point($nod);
    $z=0;
    $dir_routes = array();
    for ($i=0; $i<count($this -> routes); $i++) {
      if ($this -> routes[$i][count($this -> routes[$i])-2] == $end) {
        $dir_routes[$z] = $this -> routes[$i];
        $z++;
      }
    }
    $this-> routes = $dir_routes;
  }
  function minimal_route($nod, $end) {
    graph::paths_from_point_to_point($nod,$end);
    $z=0;
    $dir_routes = array();
    $pos=0;
    $min=$this -> routes[$pos]["dist"];
    for ($i=1; $i<count($this -> routes);$i++) {
      if ($this -> routes[$i]["dist"] < $min){
        $min=$this -> routes[$i]["dist"];
        $pos=$i;
      }
    }
    $this-> routes = $this -> routes[$pos];
  }
}
//---------------------- graph class -------------------------------------------


?>
