/*
 * hid driver for the nordic52840 SoCs
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#ifndef __HID_NORDIC52840_H_
#define __HID_NORDIC52840_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/hiddev.h>
#include <linux/hid-debug.h>
#include <linux/hidraw.h>
#include <uapi/linux/hid.h>
#include <linux/dma-buf.h>
#include <linux/kobject.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>
#include <linux/types.h>

/*************************macro configuration*******************/
#define MAX_PACK_SIZE 100
#define CMD_REQUEST_TAG (0x00A8)

#define MAX_PACK_SIZE 100 
#define MAX_DATA_SIZE 32
#define REPORT_SIZE 64
#define PACKET_SIZE 30

/************************type definition**********************/
typedef struct {
    uint64_t ts;
    uint32_t size;
    uint8_t data[MAX_DATA_SIZE];
} d_packet_t; 


typedef struct {
    volatile int8_t c_head;
    volatile int8_t p_head;
    volatile int8_t packDS;
    d_packet_t  data[MAX_PACK_SIZE];
}cp_buffer_t;

struct js_spi_client {
    int memfd;
    struct mutex js_sm_mutex; /*dma alloc and free mutex*/
    struct mutex js_mutex;
    void *vaddr;
    size_t vsize;
    struct dma_buf *js_buf;
    spinlock_t smem_lock;
    wait_queue_head_t  wait_queue;
    atomic_t dataflag;
    atomic_t userRequest; //request from userspace
    atomic_t nordicAcknowledge; //ack from nordic52832 master
    unsigned char JoyStickBondState; //1:left JoyStick 2:right JoyStick
    struct hid_device *hdev;
    uint8_t data[REPORT_SIZE];
    uint8_t data_buffer_empty;
    uint8_t dataSend[REPORT_SIZE];
    int exsit;
};

/***********Protocol commands to interact with framework native********/
typedef enum _requestType_t
{
    getMasterNordicVersionRequest = 1,
    setVibStateRequest,
    bondJoyStickRequest,
    disconnectJoyStickRequest,
    getJoyStickBondStateRequest,
    EnterDfuStateRequest,
    getLeftJoyStickProductNameRequest,
    getRightJoyStickProductNameRequest,
    getLeftJoyStickFwVersionRequest,
    getRightJoyStickFwVersionRequest,
    bondJoyStickStopRequest,
    getMasterNordicCurrentMode,
    nodifyAPCameraStrobe,
    invalidRequest,
}requestType_t;

typedef struct _request_t
{
    struct _requestHead
    {
        unsigned char requestType:7;
        unsigned char needAck:1;  //1:need to ack 0:don't need to ack
    } requestHead;
    unsigned char requestData[3];
}request_t;

typedef struct _acknowledge_t
{
    struct _acknowledgeHead
    {
        unsigned char requestType:7;
        unsigned char ack:1;  //1:ack 0:not ack
    } acknowledgeHead;
    unsigned char acknowledgeData[3];
}acknowledge_t;

#endif