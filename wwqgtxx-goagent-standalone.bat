:: wwqgtxx-goagent-standalone.bat
:: Main Batch File - GoAgent Only, Use your own browser

@echo off
title Starting wwqgtxx-goagent FanQiang software suite...

call genhash.inc.bat
call update.inc.bat
call miscellaneous.inc.bat
:: pause
call startgoagent.inc.bat