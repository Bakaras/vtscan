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

if [ -z "$1" ]
then
 echo "No argument supplied. exit."
 exit 0
fi

NL=$'\n'
BASH_PID=${BASHPID}

debug() {
 if [ "${DEBUG}" = "YES" ]
 then
  if [ "${TERM}" = "dumb" ]
  then
   /usr/bin/logger -t vtscan-${BASH_PID} -p mail.debug "== $@"
  else
   echo "== $@"
  fi
 fi
}

log() {
  if [ "${TERM}" = "dumb" ]
  then
   /usr/bin/logger -t vtscan-${BASH_PID} -p mail.info "= $@"
  else
   echo "= $@"
  fi
}

logresult() {
 log " ${PART_FILE_MIME_TYPE} KNOWN=${RESP_CODE} positives=${POSITIVES} VIRUS_FOUND=${VIRUS_FOUND} CACHE_HIT=${CACHE_HIT} DETECTED=${VIRUS_NAME}"
}

readcache() {
   # read cache:
   /usr/bin/dotlockfile -r 3 ${CACHEDIR}/cachelock
   RESULT=$?
   if [ ${RESULT} != 0 ]; then log " Cache locked..."; return; fi
    VT_REPORT_JSON=$(cat ${CACHEDIR}/${SHA256_SUM})
   /usr/bin/dotlockfile -u ${CACHEDIR}/cachelock
}

writecache() {
   # read cache:
   /usr/bin/dotlockfile -r 3 ${CACHEDIR}/cachelock
   RESULT=$?
   if [ ${RESULT} != 0 ]; then log " Cache locked..."; return; fi
    echo "${VT_REPORT_JSON}" > ${CACHEDIR}/${SHA256_SUM}
   /usr/bin/dotlockfile -u ${CACHEDIR}/cachelock
}

checkcache() {
   # check and clear cache:
   /usr/bin/dotlockfile -r 3 ${CACHEDIR}/cachelock
   RESULT=$?
   CACHE_HIT=0
   if [ ${RESULT} != 0 ]; then log " Cache locked..."; return; fi
   if [ -e ${CACHEDIR}/${SHA256_SUM} ]
   then
    CACHE_HIT=1
    DATE_CACHE=$(date -r ${CACHEDIR}/${SHA256_SUM} +%s)
    DATE_NOW=$(date +%s)
    DATE_DIFF=$((${DATE_NOW} - ${DATE_CACHE}))

    VT_REPORT=$(cat ${CACHEDIR}/${SHA256_SUM} | JSON.sh -b)
    KNOWN_HASH=$(echo "${VT_REPORT}" | grep -F -e "[\"response_code\"]" | cut -s -f 2)
    POSITIVES=$(echo "${VT_REPORT}" | grep -F -e "[\"positives\"]" | cut -s -f 2)

    CACHE_TTL=${KNOWN_CLEAN_CACHE_TTL}
    CACHE_VIRUS_NAME="KNOWN_CLEAN"
    if [ ${KNOWN_HASH} = 0 ]; then CACHE_TTL=${UNKNOWN_HASH_CACHE_TTL}
     CACHE_VIRUS_NAME="UNKNOWN_HASH"; fi
    if [ ${POSITIVES} -ge 1 ]; then CACHE_TTL=${KNOWN_VIRUS_CACHE_TTL}
     CACHE_VIRUS_NAME=$(echo "${VT_REPORT}" | egrep -m 1 "\[\"scans\",.*,\"result\"\]" | cut -f8 -d"\""); fi
    debug " cache age=${DATE_DIFF} CACHE_TTL=${CACHE_TTL}"

    if [ ${DATE_DIFF} -gt ${CACHE_TTL} ]
    then
     rm ${CACHEDIR}/${SHA256_SUM}
     log " Cache object=\"${CACHE_VIRUS_NAME}\" file deleted from cache age=${DATE_DIFF}"
     CACHE_HIT=0
    fi
   fi
   /usr/bin/dotlockfile -u ${CACHEDIR}/cachelock
}

apisleep() {
 if [ -n ${DELAY_SLEEP} -a "${API_ASKED}" = "yes" ]
 then
  log " delay-sleep ${DELAY_SLEEP} seconds..."
  sleep ${DELAY_SLEEP}
  log " delay-sleep end..."
 else
  if [ -z "${DELAY_SLEEP}" ]; then debug " === no delay-sleep defined..."
  elif [ "${API_ASKED}" = "no" ]; then debug " === api not asked = no delay-sleep..."
  fi
 fi
}

if [ -r /etc/vtscan/vtscan.cfg ];
then
 . /etc/vtscan/vtscan.cfg
else
 log "ERROR: Configfile /etc/vtscan/vtscan.cfg not exists or not readable"
 exit 1
fi

if [ "${VTSCAN_ENABLED}" != "YES" ]
then
 debug "INFO: vtscan not enabled. exit."
 exit 0
fi
debug "vtscan start..."

if [ -z ${URL} ]; then log "ERROR: API URL is not defined"; exit 1; fi
if [ -z ${APIKEY} ]; then log "ERROR: APIKEY is not defined"; exit 1; fi
if [ -z ${REGEX_TO_SCAN} ]; then log "ERROR: REGEX_TO_SCAN is not defined"; exit 1; fi
if [ -z ${MIN_HITS_REQUIRED} ]; then debug "MIN_HITS_REQUIRED not defined, use default (5)"; MIN_HITS_REQUIRED=5; fi

API_ASKED="no"
VIRUS_FOUND="no"
SCANNER_MESSAGE=""
SCANNERS_OUTPUT=""

TEMP_DIR=$(mktemp -dt "vtscan-XXXXXXXXXX")

SCAN_TARGET=$1
if [ -d "${SCAN_TARGET}" ]; then
  PARTS_DIR=$(readlink -f ${SCAN_TARGET})
  PARTS_DIR="${PARTS_DIR}/"
  PARTS_FILES=$(ls -1 ${PARTS_DIR})
elif [ -f "${SCAN_TARGET}" ]; then
  PARTS_FILES=$(readlink -f ${SCAN_TARGET})
else
  log "${SCAN_TARGET} not exists"
  exit 1
fi

NUM_PARTS=$(echo "${PARTS_FILES}" | wc -l)
debug " = num_parts=${NUM_PARTS}"

for PARTS_FILE in ${PARTS_FILES}
do
 SCANNERS_OUTPUT=""
 VIRUS_NAME=""
 PART="${PARTS_DIR}${PARTS_FILE}"
 PART_BASENAME=$(basename ${PART})
 PART_FILE_MIME_TYPE=$(file -b --mime-type ${PART})
 PART_FILE_SIZE=$(wc -c ${PART} | cut -d' ' -f1)

 if [[ ${PART_FILE_SIZE} -lt ${MIN_FILE_SIZE_TO_SCAN} ]]
 then
   log "${PART_FILE_MIME_TYPE} too small to scan (${PART_FILE_SIZE} bytes)"; continue
 fi

 if [[ ${PART_FILE_MIME_TYPE} =~ ${REGEX_TO_SCAN} ]]
 then
  if [ "${REGEX_TO_NOT_SCAN}" != "" ]
  then
   if [[ ${PART_FILE_MIME_TYPE} =~ ${REGEX_TO_NOT_SCAN} ]]; then log "${PART_FILE_MIME_TYPE} mime excluded from scan"; continue; fi
  fi

  debug "${PART_FILE_MIME_TYPE} mime to scan..."
  #PART_VAR=$(cat ${PART})
  #log "${PART_VAR}"
  SHA256_SUM=$(sha256sum ${PART} | awk '{print $1}')
  debug " SHA256_SUM=${SHA256_SUM}"

  checkcache
  debug " = CACHE_HIT=${CACHE_HIT}"

  if [ ${CACHE_HIT} = 1 ]
  then
   readcache
   #debug " === from cache ${VT_REPORT_JSON}"
  else
   ###
   apisleep
   ###
   debug " = curl -s -X POST ${URL} --form apikey=\"${APIKEY}\" --form resource=\"${SHA256_SUM}\" > ${TEMP_DIR}/vtreport_${PARTS_FILE}_${BASH_PID}"
   curl -s -X POST ${URL} --form apikey="${APIKEY}" --form resource="${SHA256_SUM}" > ${TEMP_DIR}/vtreport_${PARTS_FILE}_${BASH_PID}
   VT_REPORT_JSON=$(cat ${TEMP_DIR}/vtreport_${PARTS_FILE}_${BASH_PID})
   API_ASKED="yes"
   ###
  fi

  VT_REPORT=$(echo "${VT_REPORT_JSON}" | JSON.sh -b)
  if [ "${VT_REPORT}" = "" ]; then log " no vtresult = (limit...)"; continue; fi
  RESP_CODE=$(echo "${VT_REPORT}" | grep -F -e "[\"response_code\"]" | cut -s -f 2)

  if [ "x${RESP_CODE}" = "x1" ]
  then
    debug " response=${RESP_CODE} (known hash)"
    POSITIVES=$(echo "${VT_REPORT}" | grep -F -e "[\"positives\"]" | cut -s -f 2)

    if [ ${CACHE_HIT} = 0 ]
    then
      if [ ${POSITIVES} -ge ${MIN_HITS_REQUIRED} -o ${POSITIVES} -eq 0 ]; then
        debug " save new known clean or virus vtreport to cache"
        writecache
      fi
    fi

    if [ "${POSITIVES}" = "" ]; then debug " no positives in response..."; logresult; continue; fi
    if [ "${POSITIVES}" = "0" ]; then VIRUS_NAME="KNOWN_CLEAN"; logresult; continue; fi
    if [ ${POSITIVES} -ge ${MIN_HITS_REQUIRED} ]; then VIRUS_FOUND="yes"; fi

   SCANS=$(echo "${VT_REPORT}" | egrep "\[\"scans\",.*,\"detected|result\"\]" | sort)
   while read LINE
   do
    VIRUS_DETECTED=$(echo "${LINE}" | cut -f2)
    if [ "${VIRUS_DETECTED}" = "true" ]
    then
     VT_SCANNER_NAME=$(echo "${LINE}" | cut -f4 -d"\"")
     read LINE
     VT_SCANNER_VIRUS_NAME=$(echo "${LINE}" | cut -f8 -d"\"")

     debug " ${VT_SCANNER_NAME} found ${VT_SCANNER_VIRUS_NAME}"
     SCANNERS_OUTPUT+=" ${VT_SCANNER_NAME}=${VT_SCANNER_VIRUS_NAME}${NL}"

     # first name = virus name
     if [ "${VIRUS_NAME}" = "" ]; then VIRUS_NAME="${VT_SCANNER_VIRUS_NAME}_N${POSITIVES}"; fi
     if [ "${VIRUS_NAME:0:5}" = "ERROR" ]; then VIRUS_NAME="${VT_SCANNER_VIRUS_NAME}_N${POSITIVES}"; fi
    else
     VT_SCANNER_NAME=$(echo "${LINE}" | cut -f4 -d"\"")
     read LINE
    fi # if virus_detected

   done <<< "${SCANS}"
   logresult

   if [ -n ${QUARANTINEDIR} ]
   then
    if [ -d ${QUARANTINEDIR} -a -w ${QUARANTINEDIR} ]
    then
     VT_FILE=$(echo "${PART_FILE_MIME_TYPE}_${VIRUS_NAME}" | sed 's/\//_/g' | sed 's/[^a-zA-Z0-9_.\-]//g')
     TIMESTAMP=$(date '+%Y%m%d%H%M%S')
     if [ ${SAVE_INFECTED_PARTS} = "YES" ]
     then
       debug " save infected part to ${QUARANTINEDIR}/part_${BASH_PID}_${TIMESTAMP}_${PART_BASENAME}_virus_${VT_FILE}"
       cp ${PART} "/${QUARANTINEDIR}/part_${BASH_PID}_${TIMESTAMP}_${PART_BASENAME}_virus_${VT_FILE}"
       echo "${SCANNERS_OUTPUT}" > /${QUARANTINEDIR}/part_${BASH_PID}_${TIMESTAMP}_${PART_BASENAME}_virus_${VT_FILE}_scanners_output
     fi
    else
     RUN_USER=$(whoami)
     debug " ERROR: quarantinedir ${QUARANTINEDIR} not exists or not writable for user ${RUN_USER}"
    fi
   fi

   SCANNER_MESSAGE+="${PART} (${PART_FILE_MIME_TYPE}) Detected as ${VIRUS_NAME}${NL}"
   SCANNER_MESSAGE+="Positives=${POSITIVES}${NL}"
   SCANNER_MESSAGE+="${SCANNERS_OUTPUT}${NL}"
  else
   if [ "${RESP_CODE}" = "0" ]
   then
    debug " response=${RESP_CODE} (hash unknown)"
    if [ ${CACHE_HIT} = 0 ]
    then
     debug " save new unknown vtreport to cache"
     writecache
    fi # cache_hit=0
   VIRUS_NAME="UNKNOWN_HASH"
   logresult
   fi # if resp code=0
   if [ "${RESP_CODE}" = "" ]; then log " response=${RESP_CODE} (no result or error)"; fi
  fi # if resp code=1

 else
  debug "${PART} ${PART_FILE_MIME_TYPE} mime not to scan"
 fi
done # parts

rm -r ${TEMP_DIR}
debug "vtscan end..."
apisleep

if [ "${VIRUS_FOUND}" = "yes" ]
then
 echo
 echo "${SCANNER_MESSAGE}"
 exit 99
fi
exit 0
