PACKAGE=vendor.shadowcreator.hardware.nordic@1.0
LOC=default
hidl-gen -L androidbp -r vendor.shadowcreator.hardware:vendor/qcom/proprietary/interfaces -r android.hidl:system/libhidl/transport $PACKAGE
hidl-gen -o $LOC -L androidbp-impl -r vendor.shadowcreator.hardware:vendor/qcom/proprietary/interfaces -r android.hidl:system/libhidl/transport $PACKAGE
hidl-gen -o $LOC -L c++-impl -r vendor.shadowcreator.hardware:vendor/qcom/proprietary/interfaces -r android.hidl:system/libhidl/transport $PACKAGE
