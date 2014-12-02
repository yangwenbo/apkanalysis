unzip $1 -d gen_class_tmp_output
./dexdump -d gen_class_tmp_output/classes.dex | grep " invoke-" > methoddlist_to_be_done
rm -rf gen_class_tmp_output
sed -i "s/^.*}, //g" methoddlist_to_be_done
sed -i "s/:.*$//g" methoddlist_to_be_done
sed -i "s/\.//g" methoddlist_to_be_done
sort -u methoddlist_to_be_done > all_methods.dlist
rm methoddlist_to_be_done
