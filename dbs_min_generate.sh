#!/bin/bash
# rm -rf dbs_min
node autotools/dbcompiler/task.js
echo "Generated: $(date +'%d/%m/%Y')" > dbs_min/timestamp.log
