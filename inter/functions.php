<?

//obtainCorrelatedRules([...])
function obtainCorrelatedRules($fw_d,$r,$decision){
  //FIXME: we must change $RdC[$i][shadowing]=$order
  //by $RdC[$i][id]=$order;
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

//Ip2SubsetEqIp1([...])
function Ip2SubsetEqIp1($range,$ip) {
  $result = 1;

  // Matches:
  //
  // xxx.xxx.xxx.xxx        (exact)
  // xxx.xxx.xxx.[yyy-zzz]  (range)
  // xxx.xxx.xxx.xxx/nn    (nn = # bits, cisco style -- i.e. /24 = class C)
  //
  // Does not match:
  // xxx.xxx.xxx.xx[yyy-zzz]  (range, partial octets not supported)

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

//getHeader([...])
function getHeader($p,$fwName){
  //FIXME:we must replace this code with
  //alternative stuff using regular
  //expressions
  $path=explode(',',$p);
  $header[0]=NULL;
  $i=0;
  while(($i<=count($p))&&($path[$i]!=$fwName)){
      $header[$i]=$path[$i];
      $i++;
  }

  return $header;
}
//getHeader([...])

//getTail([...])
function getTail($p,$fwName){
  //FIXME:we must replace this code with
  //alternative stuff using regular
  //expressions

  $path=explode(',',$p);
  $tail[0]=NULL;
  $i=0;$j=0;

  while(($i<count($p))&&($path[$i]!=$fwName)){
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
  //FIXME:we must replace this code with
  //alternative stuff using regular
  //expressions
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
function getPaths($rm,$Z1,$Z2){
  //FIXME:we must replace this code with
  //alternative stuff using regular
  //expressions

  //FIXME: $P must be an array of paths,
  //not just a single path.
  //So, we must change the second
  //condition of the following while,
  //and to add an array element each
  //time we find a path of firewalls
  //within a minimal route from $Z1 to $Z2
  $P=NULL;
  $i=0;
  while(($i<count($rm))&&($P==NULL)){
    $zone=explode(',',$rm[$i][zone]);
    if($zone[0]==$Z1){
      if($zone[1]==$Z2){
        $P=$rm[$i][content];
      }
    }elseif($zone[0]==$Z2){
      if($zone[1]==$Z1){
        $RP=explode(",",$rm[$i][content]);
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

  $i=0;
  while((!$included)&&($i<count($inclusion))){
    if(Ip2SubsetEqIp1($inclusion[$i],$srcIP[0])){
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
//detection([...])
function detection($path,$file){

  $wcolor="red";

  //   $nodeProperties = array("cssClass"=>"auto");

  $ini= memory_get_usage();
  printf("<b> Memory Limit: </b> %sb <br>",get_cfg_var("memory_limit"));
  printf("<b> CPU Time Limit: </b> %ss <br>",get_cfg_var("max_execution_time"));
  printf("<b> Memory Allocated: </b> %u (bytes)  ~ %u (kbytes) <BR><BR>",$ini, $ini/1024);

  echo "<BR>/*Unserializing <a href=\"$path/$file\">$file</a> ....";

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
    //firewalls ............................................................
    //     $connected=Null;
    //     $logRoot  = new HTML_TreeNodeXL("", "", $nodeProperties);
    //     $logNested= &$logRoot->addItem(new HTML_TreeNodeXL("(ShowComponents)", "", $nodeProperties));
    echo "<BR>Components:<BR>";
    foreach($data[components][fw] as $fw){
      $connections=Null;

      //       $logTxt=$fw[name];
      //       $logNested->addItem(new HTML_TreeNodeXL($logTxt, "", $nodeProperties));

      echo "&nbsp;&nbsp;&nbsp;&nbsp;<i>".$fw[name]."</i><BR>";

      $connections=explode(",",$fw[connected]);
      foreach($connections as $connection){
        $connected[]="connected(".$fw[name].",".$connection.")";
      }
    }
    //     $menuLog  = new HTML_TreeMenuXL();
    //     $menuLog->addItem($logRoot);
    //     $showLog = &new HTML_TreeMenu_DHTMLXL($menuLog, array("images"=>"TMimages", "expanded"=>false));
    //     $showLog->printMenu();

    //......................................................................
    //relations:connected ..................................................
    //     $logRoot  = new HTML_TreeNodeXL("", "", $nodeProperties);
    //     $logNested= &$logRoot->addItem(new HTML_TreeNodeXL("(ShowRelations:connected)", "", $nodeProperties));

    //     //     echo "<BR>Relations:connected<BR>";
    //     //     foreach($connected as $value){
    //     //       echo "&nbsp;&nbsp;&nbsp;&nbsp;<i>".$value."</i><BR>";
    //     //       //       $logTxt=$value;
    //     //       //       $logNested->addItem(new HTML_TreeNodeXL($logTxt, "", $nodeProperties));
    //     //     }


    //     $menuLog  = new HTML_TreeMenuXL();
    //     $menuLog->addItem($logRoot);
    //     $showLog = &new HTML_TreeMenu_DHTMLXL($menuLog, array("images"=>"TMimages", "expanded"=>false));
    //     $showLog->printMenu();

    //......................................................................
    //paths ................................................................
    //     $logRoot  = new HTML_TreeNodeXL("", "", $nodeProperties);
    //     $logNested= &$logRoot->addItem(new HTML_TreeNodeXL("(ShowPaths)", "", $nodeProperties));

    // //     echo "<BR>Paths:<BR>";

    // //     foreach($data[paths][path] as $p){
    // //       echo "&nbsp;&nbsp;&nbsp;&nbsp;<i>{".$p."} in P</i><BR>";
    // //       //       $logTxt="{".$p."} in P";
    // //       //       $logNested->addItem(new HTML_TreeNodeXL($logTxt, "", $nodeProperties));
    // //     }


    //     $menuLog  = new HTML_TreeMenuXL();
    //     $menuLog->addItem($logRoot);
    //     $showLog = &new HTML_TreeMenu_DHTMLXL($menuLog, array("images"=>"TMimages", "expanded"=>false));
    //     $showLog->printMenu();



    //......................................................................
    //zones ................................................................
    //     $logRoot  = new HTML_TreeNodeXL("", "", $nodeProperties);
    //     $logNested= &$logRoot->addItem(new HTML_TreeNodeXL("(ShowZones)", "", $nodeProperties));

    echo "<BR>Zones:<BR>";

    foreach($data[zones][zone] as $z){
      echo "&nbsp;&nbsp;&nbsp;&nbsp;<i>".$z[name].":".$z[included]."</i><BR>";
      //       $logTxt=$z[name].":".$z[included];
      //       $logNested->addItem(new HTML_TreeNodeXL($logTxt, "", $nodeProperties));
    }
    //     $menuLog  = new HTML_TreeMenuXL();
    //     $menuLog->addItem($logRoot);
    //     $showLog = &new HTML_TreeMenu_DHTMLXL($menuLog, array("images"=>"TMimages", "expanded"=>false));
    //     $showLog->printMenu();


    //......................................................................
    //relations:adjacent ...................................................

    // //     echo "<BR>Relations:adjacent<BR>";

    //     $logRoot  = new HTML_TreeNodeXL("", "", $nodeProperties);
    //     $logNested= &$logRoot->addItem(new HTML_TreeNodeXL("(ShowRelations:adjacent)", "", $nodeProperties));

    // //     foreach($data[zones][adjacent] as $a){
    // //       echo "&nbsp;&nbsp;&nbsp;&nbsp;<i>adjacent($a)</i><BR>";
    // //       //       $logTxt="adjacent($a)";
    // //       //       $logNested->addItem(new HTML_TreeNodeXL($logTxt, "", $nodeProperties));
    // //     }

    //     $menuLog  = new HTML_TreeMenuXL();
    //     $menuLog->addItem($logRoot);
    //     $showLog = &new HTML_TreeMenu_DHTMLXL($menuLog, array("images"=>"TMimages", "expanded"=>false));
    //     $showLog->printMenu();


    //......................................................................
    //routes ...............................................................

    echo "<BR>Minimal Routes:<BR>";

    //     $logRoot  = new HTML_TreeNodeXL("", "", $nodeProperties);
    //     $logNested= &$logRoot->addItem(new HTML_TreeNodeXL("(ShowRoutes:RM)", "", $nodeProperties));
    foreach($data[routes][rm] as $rm){
      echo "&nbsp;&nbsp;&nbsp;&nbsp;<i>RM(".$rm[zone].")={".$rm[content]."}</i><BR>";
      //       $logTxt="RM(".$rm[zone].")={".$rm[content]."}";
      //       $logNested->addItem(new HTML_TreeNodeXL($logTxt, "", $nodeProperties));
    }
    //     $menuLog  = new HTML_TreeMenuXL();
    //     $menuLog->addItem($logRoot);
    //     $showLog = &new HTML_TreeMenu_DHTMLXL($menuLog, array("images"=>"TMimages", "expanded"=>false));
    //     $showLog->printMenu();

  }//if_false

  echo "<BR>";

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


  echo "<BR><img src=\"img/hr.gif\" border=\"0\" height=\"2\" width=\"100%\" align=\"center\"><br>";

  echo "<BR>/*InterFw analysis */<BR><BR>";

  $start = my_microtime();

  foreach($data[components][fw] as $fw){

    echo "<img src=\"img/hr.gif\" border=\"0\" height=\"2\" width=\"100%\" align=\"center\"><br><br>";
    echo "<b>FW[".$fw[name]."]</b><BR>";

    showData($fw);
    echo "<br>Default-policy = ".$fw[policy]."<BR>";

    for($i=0;$i<count($fw[rule]);$i++){

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

      echo "<BR><b>".$fw[name]."{R".($i+1)."}:</b><BR>";
      echo "Rule=";
      showRule($fw[rule][$i]);
      if((count($Zs)>1)||(count($Zd)>1)){
        echo "<BR>";
        echo "Zs={".implode(",",$Zs)."}";
        echo "<BR>Zd={".implode(",",$Zd)."}";
      }

      for($j=0;$j<count($Zs);$j++){
        for($k=0;$k<count($Zd);$k++){

          echo "<BR><BR>";
          echo "Zs={".$Zs[$j]."}";
          echo "<BR>Zd={".$Zd[$k]."}";


          //------------------------------------------------------
          //CASE 1
          if(($Zs[$j]==$Zd[$k])&&($fw[rule][$i][decision]=="accept")){
            echo "<BR>&nbsp;<font color=\"$wcolor\"><B><b> -> Reflexivity Anomaly [Case 1, both Zs and Zd are the same, and and decision points to ".$fw[rule][$i][decision].")] !!!</B></b></font>";
          }elseif($Zs[$j]!=$Zd[$k]){
            //
            //CASE 1
            //------------------------------------------------------

            //FIXME:we should change $p by $P, where $p would be
            //just an element of $P, within a foreach($P as $p) ...
            $p=getPaths($data[routes][rm],$Zs[$j],$Zd[$k]);
            if($p!=NULL){

              //------------------------------------------------------
              //CASE 2
              //
              echo "<BR>P={".$p."}";
              if((!inside($fw[name],$p))&&($fw[rule][$i][decision]=="accept")){
                echo "<BR>&nbsp;<font color=\"$wcolor\"><B><b> -> Void Anomaly [Case 2, since ".$fw[name]." is not in P and decision points to ".$fw[rule][$i][decision]."]!!!</B></b></font>";
              }elseif(inside($fw[name],$p)){
                //
                //CASE 2
                //------------------------------------------------------

                //------------------------------------------------------
                //CASE 3
                //echo "&nbsp;<i>(".$fw[name]." is in P)</i>";

                $path_u=getHeader($p,$fw[name]);
                if($path_u[0]!=NULL){
                  $pathU=implode(",",$path_u);
                  echo "<BR> PATH_U={".$pathU."}";

                  foreach($path_u as $fw_name){
                    $fw_u=getFirewall($fw_name,$data[components][fw]);
                    $Rua=obtainCorrelatedRules($fw_u,$fw[rule][$i],"accept");
                    $Rud=obtainCorrelatedRules($fw_u,$fw[rule][$i],"deny");

                    if($Rua[0]!=NULL){
                      echo "<BR><font color=green>Rua with ".$fw_name." is not empty!!!</font>";
                    }else{
                      echo "<BR><font color=green>Rua with ".$fw_name." is empty!!!</font>";
                    }

                    if($Rud[0]!=NULL){
                      echo "<BR><font color=green>Rud with ".$fw_name." is not empty!!!</font>";
                    }else{
                      echo "<BR><font color=green>Rud with ".$fw_name." is empty!!!</font>";
                    }

                    //FIXME: We must rewrite the testRedundancy function
                    //to avoid this stupid and unnecessary stuff
                    $RuaTestComplient[0]=$fw[rule][$i];
                    $RuaCounter=1;
                    foreach($Rua as $rule){
                      //FIXME: we must change shadowing by id ...
                      $anomaliesWithRua[($RuaCounter-1)]=$rule[shadowing];
                      $RuaTestComplient[$RuaCounter]=$rule;
                      $RuaCounter++;
                    }
                    $RudTestComplient[0]=$fw[rule][$i];
                    $RudCounter=1;
                    foreach($Rud as $rule){
                      //FIXME: we must change shadowing by id ...
                      $anomaliesWithRud[($RudCounter-1)]=$rule[shadowing];
                      $RudTestComplient[$RudCounter]=$rule;
                      $RudCounter++;
                    }//FIXME

                    if($fw[rule][$i][decision]=="deny"){

                      //------------------------------------------------------
                      //CASE 3.1

                      if(($Rua[0]==NULL)&&($Rud[0]==NULL)&&($fw[policy]=="open")){
                        //------------------------------------------------------
                        //CASE 3.1.5
                        echo "<BR>&nbsp;&nbsp;<font color=\"$wcolor\"><B><b> -> NoName Anomaly with ".$fw_name." [case 3.1.5]!!!</B></b></font>";
                      }elseif($Rua[0]!=NULL){
                        $RuaString=implode(",R",$anomaliesWithRua);
                        if(testRedundancy($RuaTestComplient,0)){
                          //------------------------------------------------------
                          //CASE 3.1.1
                          //FIXME: Do we really need this case???
                          //I think testRedundancy will always be false!!
                          echo "<BR>&nbsp;&nbsp;<font color=\"$wcolor\"><B><b> -> Full Spurious Anomaly with ".$fw_name."{R".$RuaString."} ";
                          echo " [case 3.1.1]!!!</B></b></font>";
                        }else{
                          //------------------------------------------------------
                          //CASE 3.1.2
                          echo "<BR>&nbsp;&nbsp;<font color=\"$wcolor\"><B><b> -> Partial Spurious Anomaly with ".$fw_name."{R".$RuaString."} ";
                          echo "[case 3.1.2]!!!</B></b></font>";
                        }//if_not_test_redundancy
                      }elseif($Rud[0]!=NULL){
                        $RudString=implode(",R",$anomaliesWithRud);
                        if(testRedundancy($RudTestComplient,0)){
                          //------------------------------------------------------
                          //CASE 3.1.3
                          echo "<BR>&nbsp;&nbsp;<font color=\"$wcolor\"><B><b> -> Full Redundancy Anomaly with ".$fw_name."{R".$RudString."} ";
                          echo " [case 3.1.3]!!!</B></b></font>";
                        }else{
                          //------------------------------------------------------
                          //CASE 3.1.4
                          echo "<BR>&nbsp;&nbsp;<font color=\"$wcolor\"><B><b> -> Partial Redundancy Anomaly with ".$fw_name."{R".$RudString."} ";
                          echo " [case 3.1.4]!!!</B></b></font>";
                        }//if_not_testRedundancy
                      }else{
                        echo "<BR>&nbsp;&nbsp;<font color=\"green\"><b> -> Case 3.1 for ".$fw_name." has been checked!</b></font>";
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
                        //                         echo "RudTestComplient:<textarea rows=10 cols=150>";
                        //                         print_r($RudTestComplient);
                        //                         echo "</textarea><BR>";
                        if(testRedundancy($RudTestComplient,0)){
                          //------------------------------------------------------
                          //CASE 3.2.1
                          //FIXME: Do we really need this case???
                          //I think testRedundancy will always be false!!
                          echo "<BR>&nbsp;&nbsp;<font color=\"$wcolor\"><B><b> -> Full Shadowing Anomaly with ".$fw_name."{R".$RudString."} ";
                          echo " [case 3.2.1]!!!</B></b></font>";
                        }else{
                          //------------------------------------------------------
                          //CASE 3.2.2
                          echo "<BR>&nbsp;&nbsp;<font color=\"$wcolor\"><B><b> -> Partial Shadowing Anomaly with ".$fw_name."{R".$RudString."} ";
                          echo " [case 3.2.2]!!!</B></b></font>";
                        }
                      }elseif($fw[policy]=="close"){
                        if($Rua[0]==NULL){
                          //------------------------------------------------------
                          //CASE 3.2.3
                          echo "<BR>&nbsp;&nbsp;<font color=\"$wcolor\"><B><b> -> Full Accessibility Anomaly with ".$fw_name." [case 3.2.3]!!!</B></b></font>";
                        }elseif(!testRedundancy($RuaTestComplient,0)){
                          $RuaString=implode(",R",$anomaliesWithRua);
                          //------------------------------------------------------
                          //CASE 3.2.4
                          echo "<BR>&nbsp;&nbsp;<font color=\"$wcolor\"><B><b> -> Partial Accessibility Anomaly with ".$fw_name."{R".$RuaString."} ";
                          echo " [case 3.2.4]!!!</B></b></font>";
                        }else{
                          echo "<BR>&nbsp;&nbsp;<font color=\"green\"><b> -> Case 3.2 for ".$fw_name." has been checked!</b></font>";
                        }//end_case_3.2
                      }else{
                        echo "<BR>&nbsp;&nbsp;<font color=\"green\"><b> -> Case 3.2 for ".$fw_name." has been checked!</b></font>";
                      }//end_case_3.2

                    }//else_decision_is_deny

                    //
                    //CASE 3.2
                    //------------------------------------------------------
                  }//foreach_path_u
                }else{
                  echo "<BR> PATH_U is empty";
                }

                //------------------------------------------------------
                //CASE 3.3
                //
                $path_d=getTail($p,$fw[name]);
                if(($path_d[0]!=NULL)&&($fw[rule][$i][decision]=="accept")){
                  //echo "<BR><font color=orange>$path_d[0]</font>";
                  $pathD=implode(",",$path_d);
                  echo "<BR>PATH_D={".$pathD."}";
                  foreach($path_d as $fw_name){
                    $fw_d=getFirewall($fw_name,$data[components][fw]);
                    $Rda=obtainCorrelatedRules($fw_d,$fw[rule][$i],"accept");

                    if($Rda[0]!=NULL){
                      echo "<BR><font color=green>Rda with ".$fw_name." is not empty!!!</font>";
                    }else{
                      echo "<BR><font color=green>Rda with ".$fw_name." is empty!!!</font>";
                    }

                    if(($Rda[0]==NULL)&&($fw[policy]=="close")){
                      echo "<BR>&nbsp;&nbsp;<font color=\"$wcolor\"><B><b> -> Full Accessibility Anomaly with ".$fw_name." [case 3.3.1]!!!</B></b></font>";
                    }elseif($Rda[0]!=NULL){
                      $RdaTestComplient[0]=$fw[rule][$i];
                      $RdaCounter=1;
                      foreach($Rda as $rule){
                        //FIXME: we must change shadowing by id ...
                        $anomaliesWithRda[($RdaCounter-1)]=$rule[shadowing];
                        $RdaTestComplient[$RdaCounter]=$rule;
                        $RdaCounter++;
                      }
                      if((!testRedundancy($RdaTestComplient,0))&&($fw[policy]=="close")){
                          $RdaString=implode(",R",$anomaliesWithRda);
                          echo "<BR>&nbsp;&nbsp;<font color=\"$wcolor\"><B><b> -> Partial Accessibility Anomaly with ".$fw_name."{R".$RdaString."} ";
                          echo " [case 3.3.2]!!!</B></b></font>";
                      }else{
                        echo "<BR>&nbsp;&nbsp;<font color=\"green\"><b> -> Case 3.3 for ".$fw_name." has been checked!</b></font>";
                      }
                    }//else
                  }//foreach_path_d
                }elseif($path_d[0]==NULL){
                  echo "<BR> PATH_D is empty";
                }else{
                  $pathD=implode(",",$path_d);
                  echo "<BR>PATH_D={".$pathD."}";
                  echo "<BR>&nbsp;&nbsp;<font color=\"green\"><b> -> Case 3.3 for ".$fw_name." has been checked!</b></font>";
                }
                //
                //CASE 3.3
                //------------------------------------------------------

              }//elseif_inside($fw[name],$p)
            }else{
              echo "&nbsp;&nbsp;&nbsp;<B><b>Path $p is NULL!!</b></B>";
            }
            echo "<BR>";
          }//elseif(Z1!=Z2)
        }//for_each_zd
      }//foreach_Zs
      echo "<BR>";
    }//foreach_rule
    echo "<BR>";
  }//foreach_fw

  $end = my_microtime();
  printf("<BR><b> /* Whole process done in %f seconds. */</b><BR>",round($end-$start,5));
  $ini= memory_get_usage();
  //printf("<b> /* Memory allocated: %u (bytes)  ~ %u (kbytes) ~ %u (mbytes) */</b><BR><BR>",$ini, $ini/1024, $ini/(1024*1024));
  printf("<b> /* Memory allocated: %u (bytes)  ~ %u (kbytes) */</b><BR><BR>",$ini, $ini/1024);

}//detection([...])
//-------------------------------------------------


//-------------------------------------------------
//testRedundancy([...])
function testRedundancy($R,$i){
  $test=false;
  if($R[$i][shadowing]!="true"){
    $j=($i+1);
    $temp=$R[$i];
    while (!$test and $j<=count($R)){
      if ($temp[decision] == $R[$j][decision]){
        $temp=exclusion($temp,$R[$j],$i,$j);
        if(emptyCondition($temp)){
          $test=true;
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

  $C= array('condition' => Null,
            'decision' => $B[decision],
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

  //for all the subconditions of rule B
  for($j=0;$j<count($Bcondition);$j++){

    //to check at the end ...
    $modified=false;

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
    }//if

  }//for_j

  //the last subcondition must be always null, as a mark of end.
  $C[condition][subcondition][$c]=Null;

  return $C;
}//exclusion([...])

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
            if(($key=="s")||($key=="d")){
              $vv=explode(',',$value);
              printf("[%s,%s]",long2ip($vv[0]),long2ip($vv[1]));
            }else{
              echo "[".$value."]";
            }
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
  }//for

  echo "<BR><BR>Number of rules = $nRules";
}//showData([...])

//showRule([...])
function showRule($R){

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
            if(($key=="s")||($key=="d")){
              $vv=explode(',',$value);
              printf("[%s,%s]",long2ip($vv[0]),long2ip($vv[1]));
            }else{
              echo "[".$value."]";
            }
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
}//showRule([...])


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




?>

