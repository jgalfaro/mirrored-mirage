<?php

/*
** Copyright (C) 2005, 2006 seres@ents-bretagne.fr
*/

include("XML/Unserializer.php");
include("XML/Serializer.php");
include("functions.php");

if ($add){
  if (file_exists($file)) {
    copy($file,"./tmp/$file_name");
    $action="./preprocessor.sh tmp/$file_name";
    system($action,$status);
  }
}

if ($clear=="1"){
  $action="rm -f ./tmp/* > /dev/null 2> /dev/null";
  system($action,$status);
  $action="rm -f ./pre/* > /dev/null 2> /dev/null";
  system($action,$status);
  $action="rm -f ./top/* > /dev/null 2> /dev/null";
  system($action,$status);
  $action="rm -f ./net/* > /dev/null 2> /dev/null";
  system($action,$status);
}

echo "<html><head></head>\n";
echo "<script language=\"javascript\">\n";
echo "function principal(file) {\n";
echo "	document.form2.txt.value=(file);\n";
echo "	return true;\n";
echo "}\n";
echo "</script>";
echo "<style type=\"text/css\">";
echo "A:link    { text-decoration:none; color:#231E88}";
echo "A:visited { text-decoration:none; color:#231E88}";
echo "A:active  { text-decoration:none; color:#881E23}";
echo "A:hover   { text-decoration:underline; color:#231E88}";
echo "</style>";

echo "</HEAD>";
echo "<BODY BACKGROUND=\"\" BGCOLOR=\"#FFFFFF\">";
echo "<BR>";
echo "<CENTER>";
echo "<TABLE width=\"90%\" border=\"0\" cellspacing=\"0\" cellpadding=\"3\">";
echo "<TR bgcolor=\"#156da6\"><TD colspan=1 bgcolor=\"#156da6\" align=left valign=top>";
echo "<FONT color=\"#ffffff\"><b>MIRAGE r<font size-=1>1.2010</font><td>";
echo "<TD colspan=1 bgcolor=\"#156da6\" align=right valign=top>";
echo "</TR>";


echo "<tr bgcolor=\"#9db9ce\"><td>";
echo "<FORM enctype=\"multipart/form-data\" method=post name=form1 action=\"$PHP_SELF\">";

echo "<input type=\"hidden\" name=\"add\" value=\"1\">";
echo "<input type=\"hidden\" name=\"clear\" value=\"0\">";
echo "<b>File:</b><input name=\"file\" size=\"34\" type=\"file\">";
echo "&nbsp;&nbsp;&nbsp;";
echo "<input type=\"submit\" value=\"Send\">";
echo "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
echo "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";

echo "<FORM method=post name=form3 action=\"$PHP_SELF\">";
echo "<input type=\"submit\" value=\"Clear and Reload\">";
echo "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
echo "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
echo "<input type=\"submit\" value=\"Remove files, Clear, and Reload\" onclick=\"document.form1.clear.value='1';document.form1.submit();\">";
echo "</FORM></form></td><td></td><td align=\"right\">&nbsp;</td></tr>";

echo "<tr bgcolor=\"#9db9ce\"><td></td><td></td><td></td></tr>";
echo "<tr bgcolor=\"#9db9ce\"><td colspan=3 align=\"left\">";


echo "<form name=\"form2\" action=\"$PHP_SELF\">";

//submitted files
$d = dir("./tmp/");
$primer=1;
while($entry=$d->read()){
  if ($entry!='.' && $entry!='..' && $entry!='CVS'){
    $pre=1;
    if($primer==1){
      echo "<b>Src:</b>&nbsp;&nbsp;";
    }
    $size=filesize("./tmp/".$entry);
    if($size<1024){
      $ssize=sprintf("%u bytes",$size);
    }elseif($size<(1024*1024)){
      $ssize=sprintf("%u KB",round($size/(1024),0));
    }else{
      $ssize=sprintf("%u MB",round($size/(1024*1024),0));
    }
    $arr=explode(".",$entry);
    if ($primer!=1){
      echo ",&nbsp;<a href=\"./tmp/".$entry."\">".$entry."</a> ($ssize)";
    } else{
      echo "<a href=\"./tmp/".$entry."\">".$entry."</a> ($ssize)";
      $primer=0;
      $firstFile=$entry;
    }
  }
}//while
$d->close();
echo "<BR><BR>";
?>
<?
//submitted files
$primer=1;
$d = dir("./pre/");
while($entry=$d->read()){
  if ($entry!='.' && $entry!='..' && $entry!='CVS'){
    $pre=1;
    if($primer==1){
      echo "<b>Files:</b>";
    }
    $size=filesize("./pre/".$entry);
    if($size<1024){
      $ssize=sprintf("%u bytes",$size);
    }elseif($size<(1024*1024)){
      $ssize=sprintf("%u KB",round($size/(1024),0));
    }else{
      $ssize=sprintf("%u MB",round($size/(1024*1024),0));
    }
    $arr=$entry;
    if ($primer!=1){
      echo ",&nbsp;<INPUT type=\"radio\" name=\"fileToTransform\" value=\"$entry\"";
      echo " checked=\"checked\" onclick=\"document.form2.outputFilename.value='output.xml'\"";
      echo "><a href=\"./pre/".$entry."\">".$entry."</a> ($ssize)";
    } else{
      echo "&nbsp;<INPUT type=\"radio\" name=\"fileToTransform\" value=\"$entry\"";
      echo " checked=\"checked\" onclick=\"document.form2.outputFilename.value='output.xml'\"";
      echo "><a href=\"./pre/".$entry."\">".$entry."</a> ($ssize)";
      $primer=0;
      $firstFile=$entry;
    }
  }
}//while
$d->close();

//submitted files
$d = dir("./top/");
$primer=1;
while($entry=$d->read()){
  if ($entry!='.' && $entry!='..' && $entry!='CVS'){
    $top=1;
    if($primer==1){
      echo "<br><br><b>Topology:</b>";
    }
    $size=filesize("./top/".$entry);
    if($size<1024){
      $ssize=sprintf("%u bytes",$size);
    }elseif($size<(1024*1024)){
      $ssize=sprintf("%u KB",round($size/(1024),0));
    }else{
      $ssize=sprintf("%u MB",round($size/(1024*1024),0));
    }
    if ($primer!=1){
      echo ",&nbsp;<INPUT type=\"radio\" name=\"fileToTransform\" value=\"$entry\"";
      if ($entry==$fileToTransform){
        echo " checked=\"checked\" onclick=\"document.form2.outputFilename.value='output.xml'\"";
      }
      echo "><a href=\"./top/".$entry."\">".$entry."</a> ($ssize)";
    } else{
      echo "&nbsp;<INPUT type=\"radio\" name=\"fileToTransform\" value=\"$entry\"";
      if (($entry==$fileToTransform)||(!isset($fileToTransform))){
        echo " checked=\"checked\" onclick=\"document.form2.outputFilename.value='output.xml'\"";
      }
      echo "><a href=\"./top/".$entry."\">".$entry."</a> ($ssize)";
      $primer=0;
      $firstFile=$entry;
    }
  }
}//while
$d->close();

//submitted files
$d = dir("./net/");
$primer=1;
while($entry=$d->read()){
  if ($entry!='.' && $entry!='..' && $entry!='CVS'){
    $net=1;
    if($primer==1){
      echo "<br><br><b>Network model:</b>";
    }
    $size=filesize("./net/".$entry);
    if($size<1024){
      $ssize=sprintf("%u bytes",$size);
    }elseif($size<(1024*1024)){
      $ssize=sprintf("%u KB",round($size/(1024),0));
    }else{
      $ssize=sprintf("%u MB",round($size/(1024*1024),0));
    }
    if ($primer!=1){
      echo ",&nbsp;<INPUT type=\"radio\" name=\"fileToTransform\" value=\"$entry\"";
      if ($entry==$fileToTransform){
        echo " checked=\"checked\" onclick=\"document.form2.outputFilename.value='output.xml'\"";
      }
      echo "><a href=\"./net/".$entry."\">".$entry."</a> ($ssize)";
    } else{
      echo "&nbsp;<INPUT type=\"radio\" name=\"fileToTransform\" value=\"$entry\"";
      if (($entry==$fileToTransform)||(!isset($fileToTransform))){
        echo " checked=\"checked\" onclick=\"document.form2.outputFilename.value='output.xml'\"";
      }
      echo "><a href=\"./net/".$entry."\">".$entry."</a> ($ssize)";
      $primer=0;
      $firstFile=$entry;
    }
  }
}//while
$d->close();

if(isset($net)){
  $saveFilename=$outputFilename;
  if(isset($outputFilename)){
    $outputFilename=$outputFilename;
  }else{
    $outputFilename="output.xml";
  }
}elseif(isset($top)){
  $saveFilename=$outputFilename;
  $outputFilename=sprintf("%s_net.xml",strtok($arr,"\_"));
}elseif(isset($pre)){
  $saveFilename=$outputFilename;
  $outputFilename=sprintf("%s_top.xml",strtok($arr,"\_"));
}

if(isset($net)){

  echo "<br><br><b>Selected component:&nbsp;&nbsp;&nbsp;</b>";
  echo "<select name=\"component\">";
  echo "<option value=\"none\">Firewalls";
  echo "<option value=\"none\">(none)";


  $options = array('parseAttributes'=>true);
  $unserializer = &new XML_Unserializer($options);
  $result = $unserializer->unserialize("./net/".$firstFile,true);
  $data = $unserializer->getUnserializedData();

  foreach($data[components][fw] as $c){
    if($c[type]=="Firewall"){
      $list[]=$c[name];
    }
  }

  if(!isset($component)){
    $component=$list[0];
  }

  foreach($list as $l){
    echo "<option value=\"$l\"";
    if($l==$component){
      echo "selected=\"selected\"";
    }
    echo ">$l</option>";
  }

  echo "<option value=\"\">     ";
  echo "<option value=\"\">NIDSs";
  echo "<option value=\"none\">(none)";

  unset($list);
  foreach($data[components][fw] as $c){
    if($c[type]=="NIDS"){
      $list[]=$c[name];
    }
  }

  foreach($list as $l){
    echo "<option value=\"$l\"";
    if($l==$component){
      echo "selected=\"selected\"";
    }
    echo ">$l</option>";
  }

  echo "</select>";

  unset($data);
}


if(isset($outputFilename)){
  echo "<BR><BR>";
  echo "<TR bgcolor=\"#9db9ce\">";
  echo "<td align=\"left\" colspan=\"3\">";
  echo "<b>Output</b>";
  echo "&nbsp;<input type=\"checkbox\" name=\"generateOutput\" value=\"true\" checked=\"checked\">";
  echo "&nbsp;<input type=\"text\" name=\"outputFilename\" value=\"$outputFilename\">";
  echo "</tr>";
}

if(isset($net)){
  echo "<TR bgcolor=\"#9db9ce\"><td align=\"left\" colspan=\"3\"><BR><b>View</b><br>&nbsp;";
  echo "<input type=\"radio\" name=\"view\" value=\"results\" checked=\"checked\">Results&nbsp;";
  echo "<input type=\"radio\" name=\"view\" value=\"all\">Logs</tr>";
}



echo "<TR bgcolor=\"#9db9ce\"><TD colspan=\"3\"></td></tr><TR><TD></td></tr><TR bgcolor=\"#9db9ce\" align=\"center\"><TD align=\"center\">";
echo "<input type=\"hidden\" name=\"transformFile\" value=\"1\">";
echo "&nbsp;";
echo "<input type=\"submit\" value=\"(1) Obtain topology\">";
echo "&nbsp;&nbsp;&nbsp;";
echo "<input type=\"button\" onclick=\"document.form2.transformFile.value='2';document.form2.submit();\" value=\"(2) Generate network model from topology\">";
echo "&nbsp;&nbsp;&nbsp;";
echo "<input type=\"button\" onclick=\"document.form2.transformFile.value='3';document.form2.submit();\" value=\"(3) Intra-component audit\">";
echo "&nbsp;&nbsp;&nbsp;";
echo "<input type=\"button\" onclick=\"document.form2.transformFile.value='4';document.form2.submit();\" value=\"(4) Inter-components audit\">";

echo "</FORM></td><td align=\"left\">";

echo "</TD></td><td align=right></TD></TR><TR><TD></td></tr>";

if($fileToTransform){
  if($transformFile=="1"){
    echo "<TR bgcolor=\"#eaeaea\"><TD colspan=3><h5>Output Window</h5>";
    echo "</td></tr><tr><td colspan=3><table border=1 width=100%><tr><td>";
    echo "<br>";
    //Call parser to extract skybox's information
    parser("./pre",$fileToTransform,$generateOutput,$saveFilename);
    echo "</h5></td></tr></table></td></tr>";
  }elseif($transformFile=="2"){
    echo "<TR bgcolor=\"#eaeaea\"><TD colspan=3><h5>Output Window</h5>";
    echo "</td></tr><tr><td colspan=3><table border=1 width=100%><tr><td>";
    echo "<br>";
    //Call postprocessor to obtain our network model
    postprocess("./top",$fileToTransform,$generateOutput,$saveFilename);
    echo "</h5></td></tr></table></td></tr>";
  }elseif($transformFile=="3"){
    echo "<TR bgcolor=\"#eaeaea\"><TD colspan=3><h5>Output Window</h5>";
    echo "</td></tr><tr><td colspan=3><table border=1 width=100%><tr><td>";
    echo "<br>";
    //Call to our intra-component audit algorithms
    detection_intra_component("./net",$fileToTransform,$generateOutput,$saveFilename,$view,$component);
    echo "</h5></td></tr></table></td></tr>";
  }elseif($transformFile=="4"){
    echo "<TR bgcolor=\"#eaeaea\"><TD colspan=3><h5>Output Window</h5>";
    echo "</td></tr><tr><td colspan=3><table border=1 width=100%><tr><td>";
    echo "<br>";
    //Call to our inter-component audit algorithms
    detection_inter_component("./net",$fileToTransform,$view);
    echo "</h5></td></tr></table></td></tr>";
  }
}

echo "</table></body></html>";
?>
