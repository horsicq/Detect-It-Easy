#!/bin/bash
./dbs_min_generate.sh
git add dbs_min/
git commit -m "dbs_min update" >/dev/null 2>&1
git push
