PACKAGE=vendor.shadowcreator.hardware.nordic@1.0
CURRENT_PATH="$(dirname $(readlink -f "$0"))"
CURRENT_FILE="${CURRENT_PATH}/../current.txt"
if [ ! -f ${CURRENT_FILE} ]
then
    touch ${CURRENT_FILE}
fi
hidl-gen -Lhash -rvendor.shadowcreator.hardware.nordic:vendor/qcom/proprietary/interfaces/nordic $PACKAGE >> ${CURRENT_FILE}