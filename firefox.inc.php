<?php
function del_dir ($dir,$type=true)
{
$n=0;
if (is_dir($dir)) {
if ($dh = opendir($dir)) {
while (($file = readdir($dh)) !== false) {
//.svn 忽略 svn 版本控制信息
if ( $file == '.' or $file =='..' or $file == '.svn')
{
continue;
}
if (is_file ($dir.$file))
{
unlink($dir.$file);
$n++;
}
if (is_dir ($dir.$file))
{
del_dir ($dir.$file.'/');
if ($type)
{
$n++;
rmdir($dir.$file.'/');
}
}
}
}
closedir($dh);
}
return $n;
}

if(file_exists("./FirefoxPortable/FirefoxPortable.exe")){
	exec('start ./FirefoxPortable/FirefoxPortable.exe "https://wwqgtxx-goagent.googlecode.com/git-history/web/ifanqiang.htm"');
}
else{
echo "Don't Have FirefoxPortable.";
@unlink("FirefoxPortable\Data\profile\cert8.db");
del_dir("FirefoxPortable\Data\profile");
del_dir("FirefoxPortable\Data");
del_dir("FirefoxPortable");
}
?>