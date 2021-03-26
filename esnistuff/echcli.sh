#!/bin/bash

# Script to run basic tests using the openssl command line tool.
# Equivalent tests should migrate to being run as part of ``make test``

# set -x

# to pick up correct .so's - maybe note 
: ${TOP=$HOME/code/openssl}
export LD_LIBRARY_PATH=$TOP

# variables/settings
# use Valgrind or not
VG="no"
# print loads or not
DEBUG="no"
# run without doing ECH at all
NOECH="no"
# whether or not to grease (only makes sense with NOECH==yes)
GREASE="no"

# Protocol parameters

DEFALPNVAL="-alpn inner,secret,h2 -alpn-outer outer,public,http/1.1"
DOALPN="yes"

# default port
PORT="443"
# port from commeand line
SUPPLIEDPORT=""
# HTTPPATH="index.html"
HTTPPATH=""

# the name or IP of the host to which we'll connect
SUPPLIEDSERVER=""
# the name that we'll put in inne CH - the ECH/SNI
SUPPLIEDHIDDEN=""

# PNO is the public_name_override that'll be sent as clear_sni
SUPPLIEDPNO=""

# ECH (or filename) from command line
SUPPLIEDECH=""

# CA info for server
SUPPLIEDCADIR=""

# stored session
SUPPLIEDSESSION=""

# default values
HIDDEN="crypto.cloudflare.com"
PNO="crypto.cloudflare.com"
#PNO="rte.ie"
CAPATH="/etc/ssl/certs/"
CAFILE="./cadir/oe.csr"
REALCERT="no" # default to fake CA for localhost
CIPHERSUITES="" # default to internal default

function whenisitagain()
{
    /bin/date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)

echo "Running $0 at $NOW"

function usage()
{
    echo "$0 [-cdfhHPpsrnlvL] - try out encrypted client hello (ECH) via openssl s_client"
	echo "  -c [name] specifices a name that I'll send as an outer SNI (NONE is special)"
    echo "  -d means run s_client in verbose mode"
    echo "  -f [pathname] specifies the file/pathname to request (default: '/')"
    echo "  -g means GREASE (only applied with -n)"
    echo "  -h means print this"
    echo "  -H means try connect to that hidden server"
    echo "  -j just use 0x1301 ciphersuite"
    echo "  -n means don't trigger ech at all"
    echo "  -p [port] specifices a port (default: 443)"
	echo "  -P [filename] means read ECHConfigs public value from file and not DNS"
    echo "  -r (or --realcert) says to not use locally generated fake CA regardless"
	echo "  -s [name] specifices a server to which I'll connect (localhost=>local certs, unless you also provide --realcert)"
	echo "  -S [file] means save or resume session from <file>"
    echo "  -v means run with valgrind"

	echo ""
	echo "The following should work:"
	echo "    $0 -H ietf.org"
    exit 99
}

# options may be followed by one colon to indicate they have a required argument
if ! options=$(/usr/bin/getopt -s bash -o c:df:ghH:jnp:P:rs:S:v -l clear_sni:,debug,filepath:,grease,help,hidden:,just,noech,port:,echpub:,realcert,server:,session:,valgrind -- "$@")
then
    # something went wrong, getopt will put out an error message for us
    exit 1
fi
#echo "|$options|"
eval set -- "$options"
while [ $# -gt 0 ]
do
    case "$1" in
        -c|--clear_sni) SUPPLIEDPNO=$2; shift;;
        -d|--debug) DEBUG="yes" ;;
        -f|--filepath) HTTPPATH=$2; shift;;
		-g|--grease) GREASE="yes";;
        -h|--help) usage;;
        -H|--hidden) SUPPLIEDHIDDEN=$2; shift;;
        -j|--just) CIPHERSUITES=" -ciphersuites TLS_AES_128_GCM_SHA256 " ;;
        -n|--noech) NOECH="yes" ;;
        -p|--port) SUPPLIEDPORT=$2; shift;;
		-P|--echpub) SUPPLIEDECH=$2; shift;;
        -r|--realcert) REALCERT="yes" ;;
        -s|--server) SUPPLIEDSERVER=$2; shift;;
        -S|--session) SUPPLIEDSESSION=$2; shift;;
        -v|--valgrind) VG="yes" ;;
        (--) shift; break;;
        (-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
        (*)  break;;
    esac
    shift
done

hidden=$HIDDEN
if [[ "$SUPPLIEDHIDDEN" != "" ]]
then
	hidden=$SUPPLIEDHIDDEN
fi

# figure out if we have tracing enabled within OpenSSL
# there's probably an easier way but s_client -help
# ought work
TRACING=""
tmpf=`mktemp`
$TOP/apps/openssl s_client -help >$tmpf 2>&1
tcount=`grep -c 'trace output of protocol messages' $tmpf`
if [[ "$tcount" == "1" ]]
then
    TRACING="-trace "
fi
rm -f $tmpf

#dbgstr=" -verify_quiet"
dbgstr=" "
#dbgstr=" "
if [[ "$DEBUG" == "yes" ]]
then
    #dbgstr="-msg -debug $TRACING -security_debug_verbose -state -tlsextdebug -keylogfile cli.keys"
    #dbgstr="-msg -debug $TRACING"
    dbgstr="-msg -debug $TRACING -tlsextdebug "
fi

vgcmd=""
if [[ "$VG" == "yes" ]]
then
    #vgcmd="valgrind --leak-check=full "
    vgcmd="valgrind --leak-check=full --error-limit=no --track-origins=yes "
fi

if [[ "$SUPPLIEDPORT" != "" ]]
then
    PORT=$SUPPLIEDPORT
fi

# Set SNI
clear_sni=$PNO
if [[ "$SUPPLIEDPNO" != "" ]]
then
    if [[ "$SUPPLIEDPNO" == "NONE" ]]
    then
        clear_sni=""
    else
        clear_sni=$SUPPLIEDPNO
    fi
fi
if [[ "$GREASE" == "yes" ]]
then
    echoutercmd=" "
else
    echoutercmd="-ech-outer $clear_sni"
fi

# Set address of target 
if [[ "$clear_sni" != "" && "$hidden" == "" ]]
then
    target=" -connect $clear_sni:$PORT "
else
    # I guess we better connect to hidden 
    # Note that this could leak via DNS again
    target=" -connect $hidden:$PORT "
fi
server=$clear_sni
if [[ "$SUPPLIEDSERVER" != "" ]]
then
	target=" -connect $SUPPLIEDSERVER:$PORT"
	server=$SUPPLIEDSERVER
fi

# set ciphersuites
ciphers=$CIPHERSUITES

if [[ "$NOECH" != "yes" ]]
then
	if [[ "$SUPPLIEDECH" != "" ]]
	then
		if [ ! -f $SUPPLIEDECH ]
		then
			echo "Assuming supplied ECH is RR value"
			ECH="$SUPPLIEDECH"
        else
		    # check if file suffix is .pem (base64 encoding) 
		    # and react accordingly, don't take any other file extensions
		    ssfname=`basename $SUPPLIEDECH`
		    if [ `basename "$ssfname" .pem` != "$ssfname" ]
		    then
			    ECH=`tail -2 $SUPPLIEDECH | head -1` 
		    else
			    echo "Not sure of file type of $SUPPLIEDECH - try make a PEM file to help me"
			    exit 8
		    fi
		fi
	else
        # try draft-09 only for now, i.e. HTTPSSVC
        # kill the spaces and joing the lines if multi-valued seen 
        qname=$hidden
        ECH=`dig +short -t TYPE65 $qname | tail -1 | cut -f 3- -d' ' | sed -e 's/ //g' | sed -e 'N;s/\n//'`
        if [[ "$ECH" == "" ]]
        then
            # TODO: do the parsing biz
            echo "Can't parse ECHO from HTTPSSVC"
        #else
            #echo "ECH from DNS is : $ECH"
        fi
	fi
fi

if [[ "$NOECH" != "yes" && "$ECH" == "" ]]
then
    echo "Not trying - no sign of ECHKeys ECH "
    exit 100
fi

echstr="-servername $hidden -svcb $ECH "
if [[ "$NOECH" == "yes" ]]
then
    echo "Not trying ECH"
    echstr="-servername $hidden "
    if [[ "$GREASE" == "yes" ]]
    then
        echo "Trying to GREASE though"
        if [[ "$SUPPLIEDPNO" == "NONE" ]]
        then
            echstr=" -noservername -ech_grease "
        else
            echstr=" -servername $clear_sni -ech_grease "
        fi
    fi
fi

#httpreq="GET $HTTPPATH\\r\\n\\r\\n"
httpreq="GET /$HTTPPATH HTTP/1.1\r\nConnection: close\r\nHost: $hidden\r\n\r\n"

# tell it where CA stuff is...
if [[ "$server" != "localhost" ]]
then
	certsdb=" -CApath $CAPATH"
else
    if [[ "$REALCERT" == "no" && -f $CAFILE ]]
    then
	    certsdb=" -CAfile $CAFILE"
    else
	    certsdb=" -CApath $CAPATH"
    fi
fi

# force tls13
force13="-no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2"
#force13="-cipher TLS13-AES-128-GCM-SHA256 -no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2"
#force13="-tls1_3 -cipher TLS13-AES-128-GCM-SHA256 "

# session resumption
session=""
if [[ "$SUPPLIEDSESSION" != "" ]]
then
	if [ ! -f $SUPPLIEDSESSION ]
	then
		# resuming 
		session=" -sess_out $SUPPLIEDSESSION"
	else
		# save so we can resume
		session=" -sess_in $SUPPLIEDSESSION"
	fi
fi

alpn=""
if [[ "$GREASE" == "no" && "$DOALPN" == "yes" ]]
then
    alpn=$DEFALPNVAL
fi

TMPF=`mktemp /tmp/echtestXXXX`

if [[ "$DEBUG" == "yes" ]]
then
    echo "Running: $TOP/apps/openssl s_client $dbgstr $certsdb $force13 $target $echstr $echoutercmd $session $alpn $ciphers"
fi
echo -e "$httpreq" | $vgcmd $TOP/apps/openssl s_client $dbgstr $certsdb $force13 $target $echstr $echoutercmd $session $alpn $ciphers >$TMPF 2>&1

c200=`grep -c "200 OK" $TMPF`
csucc=`grep -c "ECH: success" $TMPF`
c4xx=`grep -ce "^HTTP/1.1 4[0-9][0-9] " $TMPF`

if [[ "$DEBUG" == "yes" ]]
then
	echo "$0 All output" 
	cat $TMPF
	echo ""
fi
if [[ "$VG" == "yes" ]]
then
	vgout=`grep -e "^==" $TMPF`
	echo "$0 Valgrind" 
	echo "$vgout"
	echo ""
fi
goodresult=`grep -c "ECH: success" $TMPF`
echo "$0 Summary: "
allresult=`grep "ECH:" $TMPF`
rm -f $TMPF
if (( $goodresult > 0 ))
then
    echo "Looks like it worked ok"
else
    if [[ "$NOECH" != "yes" ]]
    then
        echo "Bummer - probably didn't work"
    fi
fi
echo $allresult
# exit with something useful
if [[ "$ctot" == "1" && "$c4xx" == "0" ]]
then
    exit 0
else
    exit 44
fi 
exit 66
