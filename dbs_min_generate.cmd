@echo off
:: rd dbs_min /q /s
node autotools\dbcompiler\task.js
echo Generated: %DATE%>dbs_min\timestamp.log
call db_compress