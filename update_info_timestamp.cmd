@echo off

echo date=%DATE%> db\info.ini
echo date=%DATE%> db_extra\info.ini

git add db\info.ini db_extra\info.ini
git commit -m "Updated timestamp for info.ini" >nul 2>&1 && git push

echo Date updated in db\info.ini and db_extra\info.ini to %DATE%