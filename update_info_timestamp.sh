#!/bin/bash

echo "date=$(date +'%Y-%m-%d')" | tee db/info.ini db_extra/info.ini > /dev/null

git add db/info.ini db_extra/info.ini

git commit -m "Updated timestamp for info.ini" >/dev/null 2>&1 && git push

echo "Date updated in db/info.ini and db_extra/info.ini to the current date"