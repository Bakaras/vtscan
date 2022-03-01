#!/bin/bash

LANG=C
LANGUAGE=C
LC_ALL=C
LC_ADDRESS=C
LC_COLLATE=C
LC_CTYPE=C
LC_IDENTIFICATION=C
LC_MEASUREMENT=C
LC_MESSAGES=C
LC_MONETARY=C
LC_NAME=C
LC_NUMERIC=C
LC_PAPER=C
LC_TELEPHONE=C
LC_TIME=C

declare -i AGE
declare -i NUM_WIPED

NL=$'\n'

function usage {
    echo "Clean old vtscan cache entries"
    echo "Usage: $0 {show|wipeunknown|wipeclean|wipevirus|wipeall|clearcache}"
}

function wipe {
    /usr/bin/dotlockfile -r 3 ${CACHEDIR}/cachelock
    rm $1
    /usr/bin/dotlockfile -u ${CACHEDIR}/cachelock
}

if [[ ! -n $1 ]];
then
  usage ; exit 1
fi

if [ "$1" = "show" -o "$1" = "wipeunknown" -o "$1" = "wipeclean" -o "$1" = "wipevirus" -o "$1" = "wipeall" -o "$1" = "clearcache" ]
then
  WIPE=$1
  echo "${WIPE} vtscan cache"
else
  usage ; exit 1
fi


if [ -r /etc/vtscan/vtscan.cfg ];
then
 . /etc/vtscan/vtscan.cfg
else
 log "ERROR: Configfile /etc/vtscan/vtscan.cfg not exists or not readable"
 exit 1
fi

CACHE_SIZE=$(ls -A ${CACHEDIR} | wc -l)
echo "cache_size=${CACHE_SIZE}"

if [ ${CACHE_SIZE} = 0 ]; then echo "cachedir ${CACHEDIR} is empty, exit."; exit 0; fi

if [ "${WIPE}" = "clearcache" ]; then
  read -p "Delete all? (y/N)" -n 1 -r
  if [[ ! $REPLY =~ ^[Yy]$ ]]
  then
    exit 1
  else
    echo
  fi
fi

   NUM_WIPED=0
   for CACHE_FILE in ${CACHEDIR}/*
   do
    #echo "=${CACHE_FILE}="
    FILE_NAME=$(basename ${CACHE_FILE})
    DATE_CACHE=$(date -r ${CACHE_FILE} +%s)
    DATE_NOW=$(date +%s)
    DATE_DIFF=$((${DATE_NOW} - ${DATE_CACHE}))
    FILE_NAME=$(basename ${CACHE_FILE})
    VTRESULT=$(cat ${CACHE_FILE} | JSON.sh -b)
    KNOWN_HASH=$(echo "${VTRESULT}" | grep -F -e "[\"response_code\"]" | cut -s -f 2)
    POSITIVES=$(echo "${VTRESULT}" | grep -F -e "[\"positives\"]" | cut -s -f 2)
    unset VIRUS_NAME
    VIRUS_NAME=$(echo "${VTRESULT}" | egrep "\[\"scans\",.*,\"result\"\]" | sort | cut -f2 | grep -v -i error | grep -v null | awk -F\" '{print $2}' | head -n1)

    unset DETECTION
    unset AGE

    if [ ${KNOWN_HASH} = 1 ]; then
     if [ ${POSITIVES} -ge 1 ]; then DETECTION="known VIRUS"; else DETECTION="known CLEAN"; fi
    else
     DETECTION="unknown hash"
    fi

    AGE=0
    case ${DETECTION}
    in
     "known VIRUS")
      if [ ${DATE_DIFF} -gt ${KNOWN_VIRUS_CACHE_TTL} ]; then AGE=$((${DATE_DIFF} - ${KNOWN_VIRUS_CACHE_TTL})); fi
     ;;
     "known CLEAN")
      if [ ${DATE_DIFF} -gt ${KNOWN_CLEAN_CACHE_TTL} ]; then AGE=$((${DATE_DIFF} - ${KNOWN_CLEAN_CACHE_TTL})); fi
     ;;
     "unknown hash")
      if [ ${DATE_DIFF} -gt ${UNKNOWN_HASH_CACHE_TTL} ]; then AGE=$((${DATE_DIFF} - ${UNKNOWN_HASH_CACHE_TTL})); fi
     ;;
     *)
      echo "error"
     ;;
     esac

    if [ "${WIPE:0:4}" = "show" ]
    then
      if [ ${AGE} = 0 ]
      then
        echo "${FILE_NAME} valid ${DETECTION} ${VIRUS_NAME}"
      else
        echo "${FILE_NAME} OLD ${DETECTION} age=${AGE}"
      fi
    fi

    if [ "${WIPE}" = "clearcache" ]
    then
      wipe ${CACHE_FILE}; ((NUM_WIPED++));
      echo "${FILE_NAME} ${DETECTION} age=${AGE} wiped ${VIRUS_NAME}"
    fi

    if [ "${WIPE:0:4}" = "wipe" ]
    then
     if [ ${AGE} -gt 1 ]
     then
      if [ "${WIPE}" = "wipeall" ]; then wipe ${CACHE_FILE}; ((NUM_WIPED++)); echo "${FILE_NAME} ${DETECTION} age=${AGE} wiped"; fi
      if [ "${WIPE}" = "wipeunknown" -a "${DETECTION}" = "unknown hash" ]; then wipe ${CACHE_FILE}; ((NUM_WIPED++)); echo "${FILE_NAME} ${DETECTION} age=${AGE} wiped"; fi
      if [ "${WIPE}" = "wipeclean" -a "${DETECTION}" = "known CLEAN" ]; then wipe ${CACHE_FILE}; ((NUM_WIPED++)); echo "${FILE_NAME} ${DETECTION} age=${AGE} wiped"; fi
      if [ "${WIPE}" = "wipevirus" -a "${DETECTION}" = "known VIRUS" ]; then wipe ${CACHE_FILE}; ((NUM_WIPED++)); echo "${FILE_NAME} ${DETECTION} age=${AGE} wiped"; fi
     fi
    fi

   done

   if [ "${WIPE:0:4}" = "wipe" -o "${WIPE}" = "clearcache" ]; then echo "NUM_WIPED=${NUM_WIPED}"; fi

exit 0
