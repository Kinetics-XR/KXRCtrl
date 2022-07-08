/*
 * hid driver for the nordic52840 SoCs
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include "hid_nordic52840.h"

#define DEBUG

static struct js_spi_client *gspi_client = NULL;
static struct kobject *sc_nordic52840_kobj = NULL;
static cp_buffer_t *u_packet = NULL; 

static void d_packet_set_instance(cp_buffer_t *in)
{
    if(gspi_client == NULL)
    {
        pr_err("js %s: drv init err", __func__);
    }

    spin_lock(&gspi_client->smem_lock);

    if(in == NULL)
    {
        u_packet = NULL;
    }
    else
    {
        u_packet = in;
        u_packet->c_head = -1;
        u_packet->p_head = -1;
    }
    
    spin_unlock(&gspi_client->smem_lock);
    
    if(in == NULL)
        pr_err("js %s:  release mem", __func__);
    else
        pr_err("js %s:  alloc mem", __func__);

}

static ssize_t jsmem_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", gspi_client->memfd);
}

static ssize_t jsmem_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    int ret;
    cp_buffer_t * inbuf;

    ret = kstrtoint(buf, 10, &gspi_client->memfd);
    if (ret < 0)
        return ret;

    pr_debug("[%s]memfd:%d\n", __func__, gspi_client->memfd);
    mutex_lock(&gspi_client->js_sm_mutex);
    
    if (gspi_client->memfd == -1)
    {
        if (IS_ERR_OR_NULL(gspi_client->vaddr))
            goto __end;
        
        d_packet_set_instance(NULL);
        dma_buf_kunmap(gspi_client->js_buf, 0, gspi_client->vaddr);
        dma_buf_end_cpu_access(gspi_client->js_buf, DMA_BIDIRECTIONAL);
        dma_buf_put(gspi_client->js_buf);
        gspi_client->vaddr = NULL;
        gspi_client->js_buf = NULL;
    }
    else
    {
        gspi_client->js_buf = dma_buf_get(gspi_client->memfd);
        if (IS_ERR_OR_NULL(gspi_client->js_buf)) {
            ret = -ENOMEM;
            pr_err("[%s]dma_buf_get failed for fd: %d\n", __func__, gspi_client->memfd);
            goto __end;
        }

        ret = dma_buf_begin_cpu_access(gspi_client->js_buf, DMA_BIDIRECTIONAL);
        if (ret) {
            pr_err("[%s]: dma_buf_begin_cpu_access failed\n", __func__);
            dma_buf_put(gspi_client->js_buf);
            gspi_client->js_buf = NULL;
            goto __end;
        }

        gspi_client->vsize = gspi_client->js_buf->size;
        gspi_client->vaddr = dma_buf_kmap(gspi_client->js_buf, 0);
        if (IS_ERR_OR_NULL(gspi_client->vaddr))
        {
            dma_buf_end_cpu_access(gspi_client->js_buf, DMA_BIDIRECTIONAL);
            dma_buf_put(gspi_client->js_buf);
            gspi_client->js_buf = NULL;
            pr_err("[%s]dma_buf_kmap failed for fd: %d\n",__func__,  gspi_client->memfd);
            goto __end;
        }
        
        inbuf = (cp_buffer_t *)gspi_client->vaddr;
        d_packet_set_instance(inbuf);
    }
__end:
    mutex_unlock(&gspi_client->js_sm_mutex);
    return count;
}

static ssize_t jsrequest_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    unsigned int input = 0;
    acknowledge_t nordicAck;
    int size = 0;
    const char enterDfuSymbolStr[3][15] = {{"HostNordic"},{"LeftJoyStick"},{"RightJoyStick"}};

    mutex_lock(&gspi_client->js_mutex);
    if(gspi_client->exsit)
    {
        memset(&nordicAck, 0, sizeof(acknowledge_t));
        input = atomic_read(&gspi_client->nordicAcknowledge);
        atomic_set(&gspi_client->nordicAcknowledge, 0);
        nordicAck.acknowledgeHead.requestType = ((input&0x7f000000) >> 24);
        nordicAck.acknowledgeHead.ack = ((input&0x80000000) >> 31);
        nordicAck.acknowledgeData[0] = (input&0x000000ff);
        nordicAck.acknowledgeData[1] = ((input&0x0000ff00) >> 8);
        nordicAck.acknowledgeData[2] = ((input&0x00ff0000) >> 16);
        pr_debug("wjx nordicAcknowledge:0x%x\n", input);
        if (nordicAck.acknowledgeHead.ack == 1)
        {
            switch(nordicAck.acknowledgeHead.requestType)
            {
                case getMasterNordicVersionRequest:
                    size = sprintf(buf, "masterNordic fwVersion:%d.%d\n", nordicAck.acknowledgeData[1], nordicAck.acknowledgeData[0]);
                    break;
                case bondJoyStickRequest:
                case disconnectJoyStickRequest:
                case setVibStateRequest:
                case bondJoyStickStopRequest:
                    size = sprintf(buf, "requestType:%d ack:%d\n",nordicAck.acknowledgeHead.requestType, nordicAck.acknowledgeHead.ack);
                    break;
                case EnterDfuStateRequest:
                    if(nordicAck.acknowledgeData[0] >0 && nordicAck.acknowledgeData[0] <4) {
                        size = sprintf(buf, "%s Enter DFU Mode\n", enterDfuSymbolStr[nordicAck.acknowledgeData[0]-1]);
                    } else {
                        size = sprintf(buf, "invalid requestType\n");
                    }
                    break;
                case getJoyStickBondStateRequest:
                    gspi_client->JoyStickBondState = (nordicAck.acknowledgeData[0]&0x03);
                    size = sprintf(buf, "left/right joyStick bond state:%d:%d\n", (gspi_client->JoyStickBondState&0x01), ((gspi_client->JoyStickBondState&0x02)>>1));
                    break;
                case getLeftJoyStickProductNameRequest:
                    size = sprintf(buf, "leftJoyStick productNameID:%d\n", nordicAck.acknowledgeData[0]);
                    break;
                case getRightJoyStickProductNameRequest:
                    size = sprintf(buf, "rightJoyStick productNameID:%d\n", nordicAck.acknowledgeData[0]);
                    break;
                case getLeftJoyStickFwVersionRequest:
                    size = sprintf(buf, "leftJoyStick fwVersion:%d.%d\n", nordicAck.acknowledgeData[1], nordicAck.acknowledgeData[0]);
                    break;
                case getRightJoyStickFwVersionRequest:
                    size = sprintf(buf, "rightJoyStick fwVersion:%d.%d\n", nordicAck.acknowledgeData[1], nordicAck.acknowledgeData[0]);
                    break;
                case getMasterNordicCurrentMode:
                    size = sprintf(buf, "masterNordicCurrentMode:%d\n", nordicAck.acknowledgeData[0]);
                    break;
                default:
                    size = sprintf(buf, "invalid requestType\n");
                    break;
            }
        }
        else
        {    
            size = sprintf(buf, "no need to ack\n");
        }
    }
    mutex_unlock(&gspi_client->js_mutex);
    return size;
}

static ssize_t jsrequest_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t size) 
{
  
   unsigned int input = 0;
   request_t request;
   int vibState = 0;
   int ret = 0;
   __u8 *hid_buf;

   mutex_lock(&gspi_client->js_mutex);
   if(sscanf(buf, "%x", &input) == 1)
   {        
        printk("wjx input:0x%x\n", input);
        if(gspi_client->exsit)
        {            
            hid_buf = kzalloc(256, GFP_KERNEL);
            if (hid_buf == NULL)
                return -ENOMEM;

            memset(&request, 0, sizeof(request_t));
            request.requestHead.requestType = ((input&0x7f000000) >> 24);
            request.requestData[0] = (input&0x000000ff);
            request.requestData[1] = (input&0x0000ff00);
            request.requestData[2] = (input&0x00ff0000);
            hid_buf[0] = ((input&0xff000000) >> 24);

            switch(request.requestHead.requestType)
            {
                case setVibStateRequest:
                    vibState = ((request.requestData[1] << 8) | request.requestData[0]);
                    if (vibState >= 0 && vibState <= 0xffff)
                    {
                        hid_buf[1] = request.requestData[0];
                        hid_buf[2] = request.requestData[1];
                    }
                    else
                        hid_buf[0] = 0;
                    break;
                case EnterDfuStateRequest:
                    if(request.requestData[0] > 0 && request.requestData[0] < 4)
                    {
                        hid_buf[1] = request.requestData[0];
                    }
                    else
                        hid_buf[0] = 0;
                    break;
                case bondJoyStickRequest:
                case disconnectJoyStickRequest:
                    hid_buf[1] = (request.requestData[0]&0x01);
                    break;
                case getMasterNordicVersionRequest:
                case getJoyStickBondStateRequest:
                case getLeftJoyStickProductNameRequest:
                case getRightJoyStickProductNameRequest:
                case getLeftJoyStickFwVersionRequest:
                case getRightJoyStickFwVersionRequest:
                case bondJoyStickStopRequest:
                case getMasterNordicCurrentMode:
                    break;
                default:
                    pr_debug("invalid requestType\n");
                    hid_buf[0] = 0;
                    break;
            }
            ret = hid_hw_output_report(gspi_client->hdev, hid_buf, REPORT_SIZE);
            if (ret != REPORT_SIZE)
                pr_err("[%s]hid_hw_output_report failed:%d", __func__, ret);
            kfree(hid_buf);
        }
   }
   mutex_unlock(&gspi_client->js_mutex);
   return size;
}

static struct kobj_attribute jsmem_attribute = __ATTR(jsmem, 0664, jsmem_show, jsmem_store);
static struct kobj_attribute jsrequest_attribute = __ATTR(jsrequest, 0664, jsrequest_show, jsrequest_store);

static struct attribute *attrs[] = {
        &jsmem_attribute.attr,
        &jsrequest_attribute.attr,
        NULL,
};

static struct attribute_group attr_group = {
        .attrs = attrs,
};

int nordic52840_nodify_camera_strobe_time(uint64_t strobeTime)  //unit:50us according to nordic52840 systick
{
    int ret = 0;

    if ((gspi_client != NULL) && (gspi_client->exsit) && (gspi_client->dataSend != NULL) && (strobeTime != 0))
    {
        mutex_lock(&gspi_client->js_mutex);
        memset(gspi_client->dataSend, 0, sizeof(gspi_client->dataSend));
        gspi_client->dataSend[0] = nodifyAPCameraStrobe; //cmd
        gspi_client->dataSend[1] = (strobeTime&0xff);
        gspi_client->dataSend[2] = ((strobeTime&0xff00) >> 8);
        gspi_client->dataSend[3] = ((strobeTime&0xff0000) >> 16);
        gspi_client->dataSend[4] = ((strobeTime&0xff000000) >> 24);
        gspi_client->dataSend[5] = ((strobeTime&0xff00000000) >> 32);
        gspi_client->dataSend[6] = ((strobeTime&0xff0000000000) >> 40);
        gspi_client->dataSend[7] = ((strobeTime&0xff000000000000) >> 48);
        gspi_client->dataSend[8] = ((strobeTime&0xff00000000000000) >> 56);
        //printk("dataSend:%u:%u:%u:%u:%u:%u:%u:%u\n", gspi_client->dataSend[1], gspi_client->dataSend[2], gspi_client->dataSend[3], \
        //    gspi_client->dataSend[4], gspi_client->dataSend[5], gspi_client->dataSend[6], gspi_client->dataSend[7], gspi_client->dataSend[8]);
        ret = hid_hw_output_report(gspi_client->hdev, gspi_client->dataSend, REPORT_SIZE);
        if (ret != REPORT_SIZE)
            printk("[%s]hid_hw_output_report failed:%d", __func__, ret);
        mutex_unlock(&gspi_client->js_mutex);
    }
    return ret;
}
EXPORT_SYMBOL(nordic52840_nodify_camera_strobe_time);

static int nordic52840_probe(struct hid_device *hdev,
    const struct hid_device_id *id)
{
    int ret;

    //For devices with non-standard HID report descriptors, it is
    //required to force the registration of an input device.
    hdev->quirks |= HID_QUIRK_HIDINPUT_FORCE;

    //Devices with non-standard incoming events need to use this quirk.
    hdev->quirks |= HID_QUIRK_INCREMENT_USAGE_ON_DUPLICATE;

    ret = hid_open_report(hdev);
    if (ret) {
        pr_err("%s: hid_open_report failed\n", __func__);
    }

    ret = hid_hw_start(hdev, HID_CONNECT_DEFAULT);
    if (ret) {
        pr_err("%s: hid_hw_start failed\n", __func__);
    }
    gspi_client->hdev = hdev;
    gspi_client->exsit = 1;
    printk("%s successfully\n", __func__);

    return 0;
}

static int nordic52840_raw_event(struct hid_device *hid, struct hid_report *report, u8 *data, int size)
{
    static unsigned int times = 0;
    static uint64_t startTime = 0;
    static unsigned int startIndex = 0;
    unsigned int input = 0;
    //unsigned int pksz = 0;
    unsigned int num = 0;
    bool skiprport = false;
    unsigned int hosttime = 0;
    uint64_t tts = 0;
    unsigned char *pbuf = NULL;
    int index = 0;
    uint32_t tth[8];
    uint64_t tto[8];

    tts = ktime_to_ns(ktime_get_boottime());
    times++;
    if (startTime == 0)
    {
        startTime = ktime_to_ns(ktime_get_boottime());
        startIndex = times;
    }
    if ((ktime_to_ns(ktime_get_boottime()) - startTime) >= 1000000000)
    {
        if ((times-startIndex) < 0)
            pr_debug("report frequency:%dhz size:%d\n", (0xffffffff-startIndex+times), size);
        else
            pr_debug("report frequency:%dhz size:%d\n", (times-startIndex), size);
        startIndex = 0;
        startTime = 0;
    }

    if((data == NULL) || (size == 0))
        return 0;
    
    if ((size == REPORT_SIZE) || (size == 34))
    {
        #if 0
        if ((gspi_client->data_buffer_empty) && (gspi_client->data != NULL))
        {
            memcpy(gspi_client->data, data, size);
            gspi_client->data_buffer_empty = 0;
        }
        #endif
        //pksz = *(data+4);
        //num = *(data+5);
        if (size == 34)
            num = 1;
        else
            num = 2;
        //if(num == 0 || pksz != 30)
        //{
        //    pr_err("wjx no joystick data\n");
        //    skiprport = true;
        //}

        memcpy(&hosttime, (data+0), 4);
        pbuf = (data+4);
        if(!skiprport)
        {
            /*add Protection if someone release the memory  */          
            spin_lock(&gspi_client->smem_lock);
            //pr_debug("[%s]pksz:%d num:%d\n", __func__, pksz, num);
            for(index = 0; index < num; index++)
            {
                memcpy(&tth[index], pbuf, 4);
                tto[index] = tts-(hosttime-tth[index])*100000;
                if((u_packet) && (gspi_client->vaddr))
                {
                    int8_t p_head;
                    d_packet_t *pdata;
                    //pr_debug("[%s]line:%d\n",  __func__, __LINE__);
                    p_head = (u_packet->p_head + 1) % MAX_PACK_SIZE;
                    pdata = &u_packet->data[p_head];
                    pdata->ts = tto[index];
                    pdata->size = PACKET_SIZE - 4;
                    memcpy((void*)pdata->data, (void*)(pbuf+4), PACKET_SIZE-4);
                    u_packet->p_head = p_head;        
                }                        
                pbuf += PACKET_SIZE;
            }
            spin_unlock(&gspi_client->smem_lock);
        }        
    }
    else
    {
        input = ((*data<<24)|(*(data+3)<<16)|(*(data+2)<<8)|*(data+1));
        atomic_set(&gspi_client->nordicAcknowledge, input);
    }
    //pr_debug("%s report->id:%d\n", __func__, report->id);
    return 0;
}

static void nordic52840_remove(struct hid_device *hdev)
{
    if (gspi_client != NULL)
    {
        if(gspi_client->exsit)
            hid_hw_stop(hdev);
        gspi_client->exsit = 0;
    }
}

static struct hid_device_id nordic52840_id_table[] = {
    { HID_USB_DEVICE(0x1915, 0x520C) },
    { }
};

MODULE_DEVICE_TABLE(hid, nordic52840_id_table);

static struct hid_driver nordic52840_driver = {
    .name = "nordic52840",
    .id_table = nordic52840_id_table,
    .probe = nordic52840_probe,
    .raw_event = nordic52840_raw_event,
    .remove = nordic52840_remove,
};

module_hid_driver(nordic52840_driver);

static int __init nordic52840_init(void)
{
    int ret = 0;

    gspi_client = kzalloc(sizeof(*gspi_client), GFP_KERNEL);
    if (!gspi_client) {
        
        pr_err("kzalloc memory for gspi_client fail\n");
        return -ENOMEM;
    }
    gspi_client->data_buffer_empty = 1;
    mutex_init(&(gspi_client->js_mutex));
    
    if (sc_nordic52840_kobj == NULL)
    {
        sc_nordic52840_kobj = kobject_create_and_add("sc_nordic52840", kernel_kobj);
        if (!sc_nordic52840_kobj) {
               pr_err("%s: create sc_nordic52840_kobj fail\n", __func__);
               ret = -ENOMEM;
               goto err_free;
        }
        ret = sysfs_create_group(sc_nordic52840_kobj, &attr_group);
        if (ret) {
               pr_err("%s: can't register sysfs\n", __func__);
               ret = -ENOMEM;
               goto sc_nordic52840_kobj_free;
        }
    }

    return ret;
sc_nordic52840_kobj_free:
    kobject_del(sc_nordic52840_kobj);
    sc_nordic52840_kobj = NULL;
err_free:
    kfree(gspi_client);
    return ret;
}

static void __exit nordic52840_exit(void)
{
    if (sc_nordic52840_kobj != NULL)
    {
        sysfs_remove_group(sc_nordic52840_kobj, &attr_group);
        kobject_del(sc_nordic52840_kobj);
        sc_nordic52840_kobj = NULL;
    }
    kfree(gspi_client);
}

module_init(nordic52840_init);
module_exit(nordic52840_exit);
MODULE_DESCRIPTION("kinetics nordic52840 hid_driver");
MODULE_LICENSE("GPL v2");
