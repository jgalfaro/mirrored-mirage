<?php

include("XML/Unserializer.php");
include("XML/Serializer.php");
include("functions.php");

if ($_POST[add]){
 $uploaddir = './tmp/';
 $uploadfile = $uploaddir . basename($_FILES['file']['name']);
 move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile);
}

if ($_POST[clear]){
  $accio="rm -f ./tmp/*";
  system($accio,$status);
}
?>
<html><head></head>
<style type="text/css">
A:link    { text-decoration:none; color:#231E88} /* was #505080 */
A:visited { text-decoration:none; color:#231E88 }
A:active  { text-decoration:none; color:#881E23 }
A:hover   { text-decoration:none; color:#FF0000 }
</style>

<BODY BACKGROUND="" BGCOLOR="#FFFFFF">
<BR>
<CENTER>
<TABLE width="90%" border="0" cellspacing="0" cellpadding="3">
<TR>
<!--<TD colspan=3 bgcolor="#00007e" align=left valign=top>-->
<TD colspan=2 bgcolor="#156da6" align=left valign=top>
<!--MIRAGE banner -->
<a href="/mirage"><FONT color="#ffffff"><b>MIRAGE</a> v<font size-=1>0.1.8</font> -- misconfiguration manager</b><br></font></TD>
<TD colspan=1 bgcolor="#156da6" align=right valign=top>
<a href="/mirage"><FONT color="#ffffff"><b>x</a></font></TD>
</TR>

<tr bgcolor="#ccddff">
<!--<tr bgcolor="#9db9ce">-->
	<td>
		<FORM enctype="multipart/form-data" method=post name=form1 action="<? echo "$PHP_SELF"; ?>">
			<input type="hidden" name="add" value="1">
			File:<input name="file" size="40" type="file">
	        	<input type="submit" value="Send">
		</form>
       </td>
       <td>
       </td>
       <td align="right">&nbsp;</td>

</tr>

<tr bgcolor="#ccddff">
<td></td>
<td></td>
<td></td>
</tr>

<tr bgcolor="#ccddff">
<td colspan=3 align="left">
<?
//submitted files
$d = dir("./tmp/");
echo "<b>Current files:</b>";
echo "<form method=\"post\" name=\"form3\" action=\"$PHP_SELF\">";
$primer=1;
while($entry=$d->read()){
  if ($entry!='.' && $entry!='..'){
    $arr=explode(".",$entry);
    if ($primer!=1){
      echo ",&nbsp;<INPUT type=\"radio\" name=\"fileToTransform\" value=\"$entry\"";
      if ($entry==$fileToTransform){
              echo "checked=\"checked\"";
      }
      echo "><a href=\"./tmp/".$entry."\">".$entry."</a>";
    } else{
      echo "&nbsp;<INPUT type=\"radio\" name=\"fileToTransform\" value=\"$entry\"><a href=\"./tmp/".$entry."\"";
      if (($entry==$fileToTransform)||(!isset($fileToTransform))){
              echo "checked=\"checked\"";
      }
      echo ">".$entry."</a>";
      $primer=0;
      $firstFile=$entry;
    }

  }
}//while
$d->close();
?>
</td></tr>
<TR><TD></td></tr>
<tr bgcolor="#ccddff">
<TD>

                <input type="hidden" name="transformFile" value="1">
		<input type="submit" value="IntraFW Detection and Removal on selected file">
		</FORM>
</td><td align=left>
                <FORM method=post name=form3 action="<? echo "$PHP_SELF"; ?>" >
		<input type="submit" value="Clear and Reload">
		</FORM>
</TD>
</td><td align=right>
		<FORM method=post name=form4 action="<? echo "$PHP_SELF"; ?>" >
		<input type="hidden" name="clear" value="1">
		<input type="submit" value="Remove files, Clear, and Reload">
		</FORM>
</TD></TR>

<TR><TD></td></tr>
<?
if(($_POST[transformFile]==1)&&($_POST[fileToTransform]!="")){
  echo "<TR bgcolor=\"#eaeaea\"><TD colspan=3><h5>Output Window</h5>";
  echo "</td></tr><tr><td colspan=3><table border=1 width=100%><tr><td>";


  echo "<br>";


  //Call to Discovery Function
  detection("./tmp",$_POST[fileToTransform]);



echo "</h5></td></tr></table></td></tr>";

}
?>

</table>
</body>
</html>

