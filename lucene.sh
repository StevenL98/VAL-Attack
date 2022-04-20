mkdir apache_ml
cd apache_ml
for y in {2002..2011}; do
    for m in {01..12}; do
	curl -LO "http://mail-archives.apache.org/mod_mbox/lucene-java-user/${y}${m}.mbox"
    done
done