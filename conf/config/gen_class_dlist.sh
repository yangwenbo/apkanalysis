unzip $1 -d gen_class_tmp_output
/home/dev/tools/androguard/apkanalysis/config/dexdump gen_class_tmp_output/classes.dex | grep "Class descriptor" | sort -u > class.dlist
rm -rf gen_class_tmp_output
sed -i "s/  Class descriptor  : //g" class.dlist
sed -i "s/'//g" class.dlist
sed -i "/^Landroid\/support\/v4\//d" class.dlist
mv class.dlist $2
cp object.dlist $2
cp flag.dlist $2
