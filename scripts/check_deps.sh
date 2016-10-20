#!/bin/bash
build=0
rpm=0
install=0
lib_support=$1
BUILDBINARIES="patch automake"
if [[ $lib_support -eq 1 ]] ; then
	BUILDBINARIES=$(echo "$BUILDBINARIES libtool")
fi
RPMBINARIES="rpm rpmbuild "
INSTALLBINARIES="python "
	# Check for build requirements(patch, autoconf, automake)
	for cmd in ${BUILDBINARIES} ; do
        	if ! command -v ${cmd} &> /dev/null ; then
                	build_goal[${build}]=${cmd}
			#echo ${build_goal[${build}]} ${build}
			((build+=1))
                fi
        done

	# Check for RPM requirements(rpm, rpmbuild)
	for cmd in ${RPMBINARIES} ; do
                if ! command -v ${cmd} &> /dev/null ; then
                        rpm_goal[${rpm}]=${cmd}
                        #echo ${rpm_goal[${rpm}]} ${rpm}
                        ((rpm+=1))
                fi
        done

	# Check for INSTALL requirements
	for cmd in ${INSTALLBINARIES} ; do
                if ! command -v ${cmd} &> /dev/null ; then
                        install_goal[${install}]=${cmd}
                        #echo ${install_goal[${install}]} ${install}
                        ((install+=1))
                fi
        done

echo "${build}:${build_goal[*]}|${rpm}:${rpm_goal[*]}|${install}:${install_goal[*]}"
