#!/bin/bash

httpd_file=$1

DEFAULT_PORT=8080

while  :;
do
  if [ $(grep -c ":$DEFAULT_PORT " $httpd_file) -ne 0 ] ||\
         [ $(netstat -paln | grep -c ":$DEFAULT_PORT ") -ne 0 ]; then

     DEFAULT_PORT=$((DEFAULT_PORT + 1))
  else
     break
  fi
done


CURRENT_VER=2
VHOST=$(cat <<_EOF_

#CHSTART
#CHVER $CURRENT_VER
Listen $DEFAULT_PORT
LoadModule python_module modules/mod_python.so
<VirtualHost *:$DEFAULT_PORT>
	ScriptAlias /python "/var/www/chelsio/python"
	DocumentRoot "/var/www/chelsio"
	<Directory /var/www/chelsio/python>
		PythonPath "['/var/www/chelsio/python']+sys.path"
		SetHandler mod_python
		PythonHandler mod_python.publisher
		PythonDebug on
	</Directory>
</VirtualHost>
#CHEND

_EOF_
)

if  grep -q  'chelsio' ${httpd_file} ; then 
	VERSION=$(cat $httpd_file | grep CHVER | awk '{ print $2}')
	if [ $CURRENT_VER -ne $VERSION ] ; then
		`perl -pi -e "BEGIN{undef $/;} s!CHSTART.*?#CHEND!$VHOST!sm"  ${httpd_file}`
	fi
else 
	echo -n "$VHOST" >> ${httpd_file}
fi
