# This python script is for analysing h264 meat data which contain some information such
# as bps, qp, time and so on.
# This python script will show these information of one second in a window.
#
# 
#
#

import matplotlib
matplotlib.use("TkAgg")
from matplotlib import pyplot as plt
import pylab
from pylab import *
import Tkinter

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2TkAgg

import sys
import os
import threading
import time
import pcap
import string
import socket
import struct

from grammarparser import grammar_parse
from grammarparser import grammar_parse_generate_string

import pcapMetaParser

# These val is for communicating information between producter and consumer.
class Producter(threading.Thread):
    def __init__(self, threadID, name, base_file_name, metaInstance, serv_ip, pcap_dev, source_type, debug_flag):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.metaInstance = metaInstance
        self.base_file_name = base_file_name
        self.grammar_list = []
        self.source_type = source_type
        self.serv_ip = serv_ip
        self.pcap_dev = pcap_dev
        self.debug_flag = debug_flag
        self.payload_type = -1
        self.pcap_dest_port = -1

        self.gOutMetaString = [] #This list containing some string will be used in consumer thread.

        self.make_meta_ready()

        self.protocols={socket.IPPROTO_TCP:'tcp', socket.IPPROTO_UDP:'udp', socket.IPPROTO_ICMP:'icmp'}

        self.threadLock = threading.Lock()

        if self.debug_flag == 'true':
            self.debug_file_out = open("debug-" + name + ".meta","w")
            
    def decode_ip_packet(self, s):
        d={}
        d['version']=(ord(s[0]) & 0xf0) >> 4
        d['header_len']=ord(s[0]) & 0x0f   #This is ip header length. 32bit
        d['tos']=ord(s[1])
        d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
        d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
        d['flags']=(ord(s[6]) & 0xe0) >> 5
        d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
        d['ttl']=ord(s[8])
        d['protocol']=ord(s[9])
        d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
        d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
        d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
        if d['header_len']>5:
            d['options']=s[20:4*(d['header_len']-5)]
        else:
            d['options']=None

        d['data']=s[4*d['header_len']:]

        # UDP parser:
        if d['protocol'] == socket.IPPROTO_UDP:
            udp_data = d['data']
            d['udp']={}
            d['udp']['source_port'] = socket.ntohs(struct.unpack('H',udp_data[0:2])[0])
            d['udp']['dest_port'] = socket.ntohs(struct.unpack('H',udp_data[2:4])[0])
            d['udp']['length'] = socket.ntohs(struct.unpack('H',udp_data[4:6])[0])  #including header and data
            d['udp']['headerlen'] = 2  # UDP header length. 32bit
            d['udp']['checksum'] = socket.ntohs(struct.unpack('H',udp_data[6:8])[0])
            udp_payload = udp_data[8:]   # UDP header contains 8 bytes header.

            if d['udp']['source_port'] == 53 or d['udp']['dest_port'] == 53 :
                d['udp']['type'] = 'dns'
            elif d['udp']['source_port'] == 137 or d['udp']['dest_port'] == 137:
                d['udp']['type'] = 'nbns'
            elif d['udp']['source_port'] == 123 or d['udp']['dest_port'] == 123:
                d['udp']['type'] = 'ntp'
            elif d['destination_address'] == '224.0.0.251':
                d['udp']['type'] = 'mdns'
            elif d['destination_address'] == '239.255.255.250':
                d['udp']['type'] = 'ssdp'
            else:
                maybe_rtp = {}                
                maybertp_flag_0 = (((ord(udp_payload[0]) & 0xC0) >> 6) == 2)
                # 32 is a normal rtp header length.
                maybertp_flag_1 = (len(udp_payload) > 12);
                maybertp_flag_2 = 0
                maybertp_flag_3 = 0 
                if maybertp_flag_0 and maybertp_flag_1 :
                    maybe_rtp['total_len'] = d['udp']['length'] - d['udp']['headerlen'] * 4
                    maybe_rtp['headerlen'] = 3

                    maybe_rtp['V'] = maybertp_flag_0
                    maybe_rtp['P'] = (ord(udp_payload[0]) & 0x20) >> 5
                    maybe_rtp['X'] = (ord(udp_payload[0]) & 0x10) >> 4
                    maybe_rtp['CC'] = (ord(udp_payload[0]) & 0xF)
                    maybe_rtp['PT'] = (ord(udp_payload[1]) & 0x7F)
                    maybe_rtp['SequenceNumber'] = socket.ntohs(struct.unpack('H',udp_payload[2:4])[0])
                    maybe_rtp['TimeStamp'] = socket.ntohl(struct.unpack('I',udp_payload[4:8])[0])
                
                    maybe_rtp['SSRC'] = socket.ntohl(struct.unpack('I',udp_payload[8:12])[0])
                    maybe_rtp['CSRC'] = []

                    maybertp_flag_2 = (maybe_rtp['PT'] >= 97) and (maybe_rtp['PT'] <= 200)
                    #maybertp_flag_2 = True
                if maybertp_flag_2:
                    for idx in range(maybe_rtp['CC']):
                        maybe_rtp['CSRC'].append(socket.ntohl(struct.unpack('I',udp_payload[12 + idx*4 : 16 + idx*4])[0]))
                        maybe_rtp['headerlen'] += 1
                    start_pos = 12 + maybe_rtp['CC'] * 4
                    payload_start_pos = start_pos
                    if maybe_rtp['X'] == 1:
                        maybe_rtp['headerlen'] += 1
                        maybe_rtp['X_LEN'] = socket.ntohs(struct.unpack('H',udp_payload[start_pos + 2:start_pos + 4])[0])
                        maybe_rtp['headerlen'] += maybe_rtp['X_LEN']
                        maybe_rtp['EX'] = udp_payload[start_pos + 4 : start_pos + 4 + maybe_rtp['X_LEN'] * 4]
                        payload_start_pos += (maybe_rtp['X_LEN'] + 1) * 4
                    else:
                        maybe_rtp['X_LEN'] = 0
                        maybe_rtp['EX'] = []

                    if maybe_rtp['P'] == 1:
                        maybe_rtp['P_len'] =  ord(s[d['total_len'] - 1])
                    else:
                        maybe_rtp['P_len'] = 0

                    # d['rtp']['payload_len'] = d['rtp']['total_len'] - d['udp']['headerlen'] * 4 - d['rtp']['P_len']
                    maybe_rtp['payload_len'] = maybe_rtp['total_len'] - maybe_rtp['headerlen'] * 4 - maybe_rtp['P_len']
                    maybe_rtp['payload'] = udp_payload[payload_start_pos: payload_start_pos + 4 + maybe_rtp['payload_len']]

                    if len(maybe_rtp['payload']) > 1:
                        h264_payloas_first_octet = ord(maybe_rtp['payload'][0])
                        # 0x67 SPS, 0x68 PPS 0x65 IDR, 0x61 non-IDR
                        maybertp_flag_3 = (h264_payloas_first_octet == 0x67) or (h264_payloas_first_octet == 0x68) or (h264_payloas_first_octet == 0x65) or (h264_payloas_first_octet == 0x61)
                        maybe_rtp['payload'] = 0

                #print "flag_0 : ", maybertp_flag_0
                #print "flag_1 : ", maybertp_flag_1
                #print "flag_2 : ", maybertp_flag_2
                #print "flag_3 : ", maybertp_flag_3

                if maybertp_flag_0 and maybertp_flag_1 and maybertp_flag_2 and maybertp_flag_3:
                    d['udp']['type'] = 'rtp-h264'
                    d['udp']['rtp'] = maybe_rtp
                    pass
                else:
                    d['udp']['type'] = 'other'
                
        return d

    def dumphex(self, s):
        bytes = map(lambda x: '%.2x' % x, map(ord, s))
        for i in xrange(0,len(bytes)/16):
            print '        %s' % string.join(bytes[i*16:(i+1)*16],' ')
        print '        %s' % string.join(bytes[(i+1)*16:],' ')


    def reset(self):
        self.payload_type = -1
        self.pcap_dest_port = -1

    def filter_packet(self, pktlen, data, timestamp):
        if not data:
            return

        """
        {
        PacketInfo --> timestamp=%s source_address=%d destination_address=%s tos=%d,total_len=%d 
        }
        """
        if data[12:14]=='\x08\x00':
            # RFC894 Ethernet :
            # | Destination address (6) | Source address (6) | type(2) |
            # Type:
            # 0x0800 : IP
            # 0x0806 : ARP
            # 0x8035 : RARP
            # So we only parse [14:]
            decoded = self.decode_ip_packet(data[14:])

            #print decoded['udp']
            if decoded['udp']['type'] == 'rtp':
                print decoded['udp']['rtp']['payload_len'], "  "
            if decoded['udp']['type'] == 'rtp-h264':
                if self.payload_type == -1:
                    self.payload_type = decoded['udp']['rtp']['PT']
                    print "Payload :", self.payload_type
                if self.pcap_dest_port == -1:
                    self.pcap_dest_port = decoded['udp']['dest_port']
                    print "Udp dest port : ", self.pcap_dest_port

                #if self.payload_type == decoded['udp']['rtp']['PT']:
                if self.pcap_dest_port == decoded['udp']['dest_port']:
                    #print "Inentify udp dest_port"
                    #print "Inentify rtp PT"
                    #print decoded['udp']['rtp']['payload_len'], "  "
                    #print decoded['udp']['rtp']
                    #print type(decoded['udp']['rtp']['headerlen'])
                    meta_str =  '{PacketInfo --> protocol=%s version=%d len=%d headerlen=%d clocktime=%s second=%d millisecond=%d source_address=%s destination_address=%s;}' % (
                        'rtp',
                        decoded['udp']['rtp']['V'],
                        decoded['udp']['rtp']['total_len'],
                        decoded['udp']['rtp']['headerlen'],
                        'Timt_' + time.strftime('%H:%M:%S',time.localtime(timestamp)).replace(':', '_'),
                        timestamp,
                        timestamp % 1 * 1000,
                        'IP_' + decoded['source_address'].replace('.', '_'),
                        'IP_' + decoded['destination_address'].replace('.', '_'))

                    self.process_meta_info(meta_str)

    def make_meta_ready(self):
        if self.source_type == 'file':
            filename = self.base_file_name
            f_in = open(filename,"r")
            # Read the original data and generate the output string
            whole_string = f_in.read()
            f_in.close()
            self.grammar_list = grammar_parse(whole_string)

    def run(self):
        print "Start producter", self.source_type
        self.producte_meta_info()
        print "End producter"

    def producte_meta_info(self):
        if self.source_type == 'file':
            #while True:
            for index in range(1):
                for iter in self.grammar_list:
                    ts = time.time()
                    meta_string = grammar_parse_generate_string([iter])
                    self.process_meta_info(meta_string)
                    te = time.time()
                    used_millisecond = (te - ts) * 1000
                    if 40 - used_millisecond > 0:
                        millisleep_sec = (40 - used_millisecond) / 1000
                    else:
                        millisleep_sec = 0
                    #time.sleep(millisleep_sec)
        elif self.source_type == 'pcap':
            p = pcap.pcapObject()
            #dev = pcap.lookupdev()
            dev = self.pcap_dev
            net, mask = pcap.lookupnet(dev)
            # note:    to_ms does nothing on linux
            p.open_live(dev, 1600, 0, 100)
            #p.dump_open('dumpfile')
            filter_str = 'ip src '+self.serv_ip
            #filter_str += ' and udp dst port ' + str(pcap_port)
            filter_str += ' and udp'
            print filter_str
            p.setfilter(filter_str, 0, 0)

            # First capture some packets in order to get the rtp destination port
            while 1:
                p.dispatch(1, lambda x,y,z: self.filter_packet(x,y,z))
                
    def process_meta_info(self, meta_string):
        if self.debug_flag == 'true':
            self.debug_file_out.write(meta_string + "\n")

        self.metaInstance.parser_string(meta_string)
        self.metaInstance.update_meta_info()
        iRes = self.metaInstance.generate_meta_info_string()
        if iRes:
            str_out = self.metaInstance.get_meta_string()
            self.metaInstance.clean_meta_info()
            self.threadLock.acquire()
            self.gOutMetaString.append(str_out)
            if self.debug_flag == 'true':
                self.debug_file_out.write(str_out + "\n")
            self.threadLock.release()
        
    def get_meta_info(self):
        res = None
        self.threadLock.acquire()
        if len(self.gOutMetaString) > 0:
            res = self.gOutMetaString[0]
            self.gOutMetaString.pop(0)
        self.threadLock.release()
        return res
    
class Consumer(threading.Thread):
    def __init__(self, threadID, name, metaDrawInstance, base_token_name, producter_instance, debug_flag):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.metaDrawInstance = metaDrawInstance
        self.base_token_name = base_token_name
        self.consumed_pos = 0
        self.producter_instance = producter_instance
        self.gOutMeta_sec = []
        self.gOutMeta_global = []
        self.threadLock_sizePreSec = threading.Lock()
        self.debug_flag = debug_flag

    def reset(self):
        self.producter_instance.reset()

    def run(self):
        print "Start consumer"
        self.consume_meta_info()
        print "End sonsumer"

    def consume_meta_info(self):
        idx = 0
        while True:
            str_meta = self.producter_instance.get_meta_info()
            if type(str_meta) == str:
                idx += 1
                self.metaDrawInstance.parse_string(str_meta)

                info_list = self.metaDrawInstance.get_info()
                info_list_size = len(info_list)
                if info_list_size > self.consumed_pos:
                    self.threadLock_sizePreSec.acquire()
                    list_tmp = info_list[self.consumed_pos:]
                    for iter in list_tmp:
                        self.gOutMeta_sec.append(iter)
                    self.consumed_pos = info_list_size
                    self.threadLock_sizePreSec.release()

                global_info = self.metaDrawInstance.get_global_info()
                if global_info != None:
                    self.threadLock_sizePreSec.acquire()                
                    self.gOutMeta_global.append(global_info)
                    self.threadLock_sizePreSec.release()

    def get_meta_info(self, required_type):
        res = None
        self.threadLock_sizePreSec.acquire()
        if required_type == 'global':
            if len(self.gOutMeta_global) > 0:
                res = self.gOutMeta_global[0]
                self.gOutMeta_global.pop(0)
        elif required_type == 'sec':
            if len(self.gOutMeta_sec) > 0:
                res = self.gOutMeta_sec[0]
                self.gOutMeta_sec.pop(0)
        self.threadLock_sizePreSec.release()
        return res

class Graph():
    def __init__(self, TitleName, producter_instance):
        self.producter_instance = producter_instance
        #self.name = name
        self.root = Tkinter.Tk()
        self.root.wm_title(TitleName)
        self.subplot_num = 0
        self.subplot_dict = {}
        self.line_dict = {}
        self.line_values_dict = {}
        self.widget = {}

        self.gs = matplotlib.gridspec.GridSpec(5, 4)
        self.generate_main_interface()

        self.line_statistics = None
        
    def add_subplot(self, figIn, p_i, subplot_id, subplot_ylabel, subplot_range):
        self.subplot_dict[subplot_id] = figIn.add_subplot(self.gs[p_i,:])
        self.subplot_dict[subplot_id].grid(True)
        self.subplot_dict[subplot_id].set_ylabel(subplot_ylabel)
        self.subplot_dict[subplot_id].axis(subplot_range)

    def reset_subplot(self, subplot_id, subplot_ylabel, subplot_range):
        self.subplot_dict[subplot_id].clear()
        self.subplot_dict[subplot_id].grid(True)    
        self.subplot_dict[subplot_id].set_ylabel(subplot_ylabel)
        self.subplot_dict[subplot_id].axis(subplot_range)

    def set_subplot_range(self, subplot_id, subplot_range):
        self.subplot_dict[subplot_id].axis(subplot_range)

    def add_line(self, subplot_id, line_id, xAchse, yAchse, style):
        self.line_dict[line_id] = self.subplot_dict[subplot_id].plot(xAchse,yAchse, style)
        self.line_values_dict[line_id] = [0 for x in range(200)]

    def line_append_data(self, line_id, val):
        #print "-----------"
        #print line_id
        #print self.line_values_dict[line_id]
        self.line_values_dict[line_id].append(val)

    def plot_line(self, subplot_id, line_data):
        #self.line_dict[line_id]
        #self.line_values_dict[line_id].append(val)        
        self.subplot_dict[subplot_id].plot(line_data)
        #axes[index][1].plot([statis_data_show['mean'], statis_data_show['mean']], [0, 0.3])

    def line_values_len(self, line_id):
        return len(self.line_values_dict[line_id])

    def update_line_show_data(self,line_id,  currentRange, NumberSamples):
        self.line_dict[line_id][0].set_data(currentRange, pylab.array(self.line_values_dict[line_id][-NumberSamples:]))

    def generate_main_interface(self):
        self.widget['h264Plot'] = self.add_graph_subplot()
        #self.widget['networkPlot'] = self.add_subplot_h264()
        pass

    def add_graph_subplot(self):
        plot_dict = {}
        plot_dict['fig'] = pylab.figure(1)
        plot_dict['frame_main_plot'] = Tkinter.Frame(self.root)
        plot_dict['frame_graph_fig'] = Tkinter.Frame(plot_dict['frame_main_plot'])
        plot_dict['frame_graph_info'] = Tkinter.Frame(plot_dict['frame_main_plot'])

        plot_dict['frame_graph_control'] = Tkinter.Frame(plot_dict['frame_graph_info'])
        plot_dict['frame_graph_text'] = Tkinter.Frame(plot_dict['frame_graph_info'])

        plot_dict['canvas'] = FigureCanvasTkAgg(plot_dict['fig'], master=plot_dict['frame_graph_fig'])
        plot_dict['canvas'].show()
        
        # Add matlotlib toolbar
        plot_dict['button_quit'] = Tkinter.Button(master=plot_dict['frame_graph_control'], text='Quit', command= lambda: self._quit())
        plot_dict['button_reset'] = Tkinter.Button(master=plot_dict['frame_graph_control'], text='Reset', command=lambda :self.reset())

        # Add matlotlib toolbar
        plot_dict['wScale'] = Tkinter.Scale(master=plot_dict['frame_graph_control'],from_=10, to=5500,sliderlength=30, label="X",orient=Tkinter.HORIZONTAL)
        plot_dict['wScale'].set(100)

        # Add matlotlib toolbar
        plot_dict['wScale_udp_packet'] = Tkinter.Scale(master=plot_dict['frame_graph_control'],from_=1, to=50,sliderlength=30, label="UDP-kbps",orient=Tkinter.HORIZONTAL)
        plot_dict['wScale_udp_packet'].set(5)

        # Add matlotlib toolbar
        plot_dict['toolbar'] = NavigationToolbar2TkAgg(plot_dict['canvas'], plot_dict['frame_graph_info'])
        plot_dict['toolbar'].update()

        plot_dict['wScale'].pack(side=Tkinter.LEFT)
        plot_dict['wScale_udp_packet'].pack(side=Tkinter.LEFT)
        plot_dict['button_quit'].pack(side=Tkinter.RIGHT)
        plot_dict['button_reset'].pack(side=Tkinter.RIGHT)

        # Add matlotlib toolbar
        plot_dict['TextInfo'] = Tkinter.Text(plot_dict['frame_graph_text'], height=6)
        plot_dict['TextInfo_timeinfo'] = Tkinter.Text(plot_dict['frame_graph_text'], height=6)

        plot_dict['TextInfo_timeinfo'].pack(side=Tkinter.TOP, fill=Tkinter.BOTH, expand=1)
        plot_dict['TextInfo'].pack(side=Tkinter.TOP,fill=Tkinter.BOTH, expand=1)

        plot_dict['canvas'].get_tk_widget().pack(side=Tkinter.TOP, fill=Tkinter.BOTH, expand=1)

        plot_dict['frame_graph_text'].pack(side=Tkinter.TOP, fill=Tkinter.BOTH, expand=1)
        plot_dict['frame_graph_control'].pack(side=Tkinter.TOP, fill=Tkinter.BOTH, expand=1)

        plot_dict['frame_graph_fig'].pack(side=Tkinter.TOP, fill=Tkinter.BOTH, expand=1)
        plot_dict['frame_graph_info'].pack(side=Tkinter.TOP, fill=Tkinter.BOTH, expand=1)
        plot_dict['frame_main_plot'].pack(side=Tkinter.LEFT, fill=Tkinter.BOTH, expand=1)

        #add subplot
        self.add_subplot(plot_dict['fig'], 0, 'ax_0_0', "udp-0", [0,1000,700,5000])
        self.add_subplot(plot_dict['fig'], 1, 'ax_1_0', "udp-1", [0,1000,700,5000])
        #self.add_subplot(plot_dict['fig'], 2, 'ax_2_0', "udp-2", [0,1000,700,5000])
        #self.add_subplot(plot_dict['fig'], 3, 'ax_3_0', "udp-3", [0,1000,700,5000])
        #self.add_subplot(plot_dict['fig'], 4, 'ax_4_0', "udp-4", [0,1000,700,5000])

        xAchse = pylab.arange(0,100,1)
        yAchse = pylab.array([0] * 100)        
        self.add_line('ax_0_0', 'udp', xAchse, yAchse, '-')

        return plot_dict
                
    def run(self):
        #root.protocol("WM_DELETE_WINDOW", _quit)  
        self.root.after(0, lambda: self.__SinwaveformGenerator())
        self.root.after(0, lambda: self.__RealtimePloter())

        self.root.protocol("WM_DELETE_WINDOW", lambda: self._quit())
        Tkinter.mainloop()

    def _quit(self):
        self.root.quit()     # stops mainloop
        self.root.destroy()  # this is necessary on Windows to prevent

    def reset(self):
        self.widget['h264Plot']['wScale'].set(100)
        
        len_tmp = 200
        NumberSamples=min(len_tmp, self.widget['h264Plot']['wScale'].get())
        NumberUdpPacket = self.widget['h264Plot']['wScale_udp_packet'].get()        
        CurrentXAxis=pylab.arange(len_tmp - NumberSamples,len_tmp,1)

        self.reset_subplot('ax_0_0', "udp", [CurrentXAxis.min(), CurrentXAxis.max(), 0, 1000 * NumberUdpPacket])

        xAchse = pylab.arange(0,100,1)
        yAchse = pylab.array([0] * 100)
        self.add_line('ax_0_0', 'udp', xAchse, yAchse, '-')
        self.add_line('ax_0_0', 'upd_bitrate', xAchse, yAchse, '-')

        text_info = "Reset Data and redraw all data."
        self.widget['h264Plot']['TextInfo'].config(state=Tkinter.NORMAL)
        self.widget['h264Plot']['TextInfo'].insert('1.0', text_info + "\n")
        self.widget['h264Plot']['TextInfo'].config(state=Tkinter.DISABLED)

        self.widget['h264Plot']['TextInfo_timeinfo'].config(state=Tkinter.NORMAL)
        self.widget['h264Plot']['TextInfo_timeinfo'].delete('1.0', Tkinter.END)
        self.widget['h264Plot']['TextInfo_timeinfo'].config(state=Tkinter.DISABLED)

        self.widget['h264Plot']['canvas'].draw()

        #self.producter_instance_1.reset()
        self.producter_instance.reset()
        
    def __RealtimePloter(self):
        len_tmp = self.line_values_len('udp')
        NumberSamples=min(len_tmp, self.widget['h264Plot']['wScale'].get())
        CurrentXAxis=pylab.arange(len_tmp - NumberSamples,len_tmp,1)
        NumberUdpPacket = self.widget['h264Plot']['wScale_udp_packet'].get()
        self.set_subplot_range('ax_0_0', [CurrentXAxis.min(), CurrentXAxis.max(), 0, 1000 * NumberUdpPacket])        
    
        self.update_line_show_data('udp', CurrentXAxis, NumberSamples)
        
        self.widget['h264Plot']['canvas'].draw()
        self.root.after(10, lambda: self.__RealtimePloter())

    def __SinwaveformGenerator(self):
        res_sec = self.producter_instance.get_meta_info('sec')
        if res_sec != None:
            udp_packet_len = res_sec['total_payload_len_kbps']
            self.line_append_data('udp', udp_packet_len)

            text_info = time.asctime(time.localtime(res_sec['second'])) + " udp = "
            text_info += str(udp_packet_len)
        
            self.widget['h264Plot']['TextInfo_timeinfo'].config(state=Tkinter.NORMAL)
            self.widget['h264Plot']['TextInfo_timeinfo'].insert('1.0', text_info + "\n")
            self.widget['h264Plot']['TextInfo_timeinfo'].config(state=Tkinter.DISABLED)
                        
        self.root.after(10, lambda: self.__SinwaveformGenerator())
        
# execute only if run as a script
from optparse import OptionParser
import os, sys
# Parse the command line options
parser = OptionParser (usage = "Usage: " + sys.argv[0] + " [Options]")
parser.add_option ("-d", "--debug=", dest = "debug", metavar="true|false", default="false", help="show debug information  [default: false]")
parser.add_option ("-f", "--h264-file=", dest = 'file', default=None, help="File which contain h264 meta data.")
parser.add_option ("-i", "--h264-ip=", dest = 'ip', default="127.0.0.1", help="IP address whicl will receive h264 meta data.[default: 127.0.0.1]")
parser.add_option ("-c", "--pcap-dev=", dest = "pcap_dev", default="en0", help="Pcap scratch dev.  [default: en0]")
options, other_argv = parser.parse_args ()

print options

filename = options.file
s_ip = options.ip
debug_flag = options.debug
pcap_dev = options.pcap_dev

# main thread which will generate the producter thread, consumer thread and showing graph thread.
threads = []

pcapMetaInstance =  pcapMetaParser.pcapMetaInfo()
pcapMetaDrawInstance = pcapMetaParser.pcapMetaInfoDraw()
thread_pcapMetaProducter = Producter(300, "Thread-producter-pcap", filename, pcapMetaInstance, s_ip, pcap_dev,'pcap', debug_flag)
thread_pcapMetaConsumer = Consumer(400, "Thread-consumer-pcap", pcapMetaDrawInstance, filename, thread_pcapMetaProducter, debug_flag)

thread_pcapMetaProducter.start()
thread_pcapMetaConsumer.start()

threads.append(thread_pcapMetaProducter)
threads.append(thread_pcapMetaConsumer)

graph_instance = Graph("Extended Realtime Plotter", thread_pcapMetaConsumer)
graph_instance.run()

#for t in threads:
#    t.join()

os.system("ps -aex | grep \"python\" | grep \"netGraph.py\" | grep python | awk '{print $1}' | xargs kill")
print "Exiting Main Thread"

