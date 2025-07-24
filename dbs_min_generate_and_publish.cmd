@echo off
call dbs_min_generate.cmd
git add dbs_min\
git commit -m "dbs_min update" >nul 2>&1 && git push