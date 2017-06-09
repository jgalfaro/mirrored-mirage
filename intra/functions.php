<?

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

//-------------------------------------------------
//detection([...])
function detection($path,$file){
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

  echo "<BR>";
  echo "<b>/*Motivation Example*/</b>";
  echo"<BR><BR>";
  showData($data);
  echo "<BR><BR>";

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

  if(isset($ip)){
    echo "<BR>";
    echo "<b>/*Transformation from IPv4-dotted-format to long-integer-format*/</b>";
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
    echo "<b>/* phase 1, step = $step, i = $rule */</b><BR>";

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
    showData($data);
    echo"<BR><BR>";
  }//for_i
  //phase 2
  for($i=0;$i<(count($data[rule]));$i++){
    $step=$i+1;
    $rule=$i+1;
    echo "<b>/* phase 2, step = $step, i = $rule */</b><BR>";
    if(testRedundancy($data[rule],$i)){
      echo "<b>/* testRedundancy(R$rule) == true */</b>";
    }else{
      echo "<b>/* testRedundancy(R$rule) == false */</b>";
    }
    echo"<BR>";

    if(testRedundancy($data[rule],$i)){
      $data[rule][$i][condition][subcondition]=",";
      $data[rule][$i][redundancy]="true";
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
    showData($data);
    echo"<BR><BR>";
    //showWarnings($data);
    //echo"<BR><BR>";
  }
  $end = my_microtime();
  //MAIN-----------------------------------

  echo "<b>/* resulting rules */</b>";
  echo"<BR><BR>";
  showResults($data);

  //It is necessary to post-process all the rules in order to detect
  //which fields were IPv4 valid address.
  if(isset($ip)){
    for($i=0;$i<count($data[rule]);$i++){
      for($j=0;$j<count($data[rule][$i][condition][subcondition]);$j++){
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

    echo "<BR><BR><BR>";
    echo "<b>/*Transformation from long-integer-format to IPv4-dotted-format*/</b>";
    echo"<BR><BR>";
    showResults($data);
    echo "<BR>";
  }

  echo"<BR><BR>";
  showWarnings($data);
  echo"<BR><BR>";
  printf("<BR><b> /* Whole process done in %f seconds. */</b><BR>",round($end-$start,5));
  $ini= memory_get_usage();
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
  }//for
  echo "<BR><BR>Number of rules == $nRules";
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
  echo "<BR><BR>Number of rules == $nRules";
}//showResults([...])


//showWarnings([...])
function showWarnings($data){
  $shown=false;
  for($i=0;$i<count($data[rule]);$i++){
    $R=$data[rule][$i];
    $fancyPosition=$i+1;
    if ($R[shadowing]=="true"||$R[redundancy]=="true"){
      if(!$shown){
        echo "<b>/* warnings */</b><BR>";
        $shown=true;
      }
      if ($R[shadowing]=="true"){
        echo "<BR>R<sub>$fancyPosition</sub>[shadowing]=true";
      }
      if ($R[redundancy]=="true"){
        echo "<BR>R<sub>$fancyPosition</sub>[redundancy]=true";
      }
    }
  }//for
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



?>

