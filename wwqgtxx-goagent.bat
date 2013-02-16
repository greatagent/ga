:: gfangqiang.bat
:: Main Batch File
   
@echo off
title wwqgtxx-goagent

call genhash.inc.bat
call update.inc.bat
call miscellaneous.inc.bat
call startgoagent.inc.bat

call startfirefox.inc.bat