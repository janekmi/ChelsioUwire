#!/bin/bash
lib_build=`pwd` ;\
all_libs=(libcxgb4_udp libcxgb4_sock libwdtoe) ;\
#echo $lib_build
for lib in ${all_libs[*]} ; do \
        if [ ! -d ${lib_build}/${lib}_debug ] ; then \
                cp -rf ${lib_build}/${lib} ${lib_build}/${lib}_debug > cp_lib.log 2>&1 ; \
        fi;\
done; 
