#!/bin/bash

cd /home/stanley/lts

rm -f 1.tt
tt=`date -d '5 minutes ago' +%Y%m%d_%H" "%M|awk '{printf("%s%02d"), $1, int($2/5)*5}'`
grep "/lts/play" /home/stanley/lts/logs/access_${tt}.log |awk -F'"|=|&' '{count[$5]+=1}END{for (i in count) print "update rank set total_rk=total_rk+"count[i]" where book_id="i}' > 1.tt

while read rank
do
`mysql -uroot -Dlts -N -s -e "set names utf8; $rank"`
done < 1.tt

rm -f 1.tt
