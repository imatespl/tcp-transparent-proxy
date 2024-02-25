#!/usr/bin/env python
#-*-coding: utf-8-*-
# Copyright (c) 2016 dwliu. See LICENSE for details.

import socket
import sys
import signal
import gevent
import ConfigParser
import struct
import time
import shelve
import re
from gevent.server import StreamServer
from gevent.event import Event
from gevent.socket import create_connection, gethostbyname
from gevent import monkey                                                                                         
monkey.patch_socket()
try:                                                                                                         
    from socket import IP_TRANSPARENT                                                                        
except ImportError:                                                                                               
    IP_TRANSPARENT = 19

from gevent.queue import Queue, Empty
tasks = Queue()

FILTER = 1
DEEP_FILTER = 2
COUNTER_FILTER = 3
XML_FILTER=4
DEFAULT_COUNTER = '0001'
CONNECTED = True
CONNECT_FAIL = False
CONNECT_STOP = 2

class PackageFilter(object):
    def __init__(self, config):
        self.cp = ConfigParser.SafeConfigParser()
        self.cp.read(config)
        self.get_filter_value()
        self.get_response_package_value()
        self.syn_ack = self.cp.get('server_mode', 'syn_ack')
        self.server_counter_side = self.cp.get('counter_save_direction', 'server_side')

    def get_filter_value(self):
        self.first_offset = int(self.cp.get('filter', 'first_offset'))
        self.first_pattern = self.cp.get('filter', 'first_pattern').decode('hex')
        self.second_offset = int(self.cp.get('filter', 'second_offset'))
        self.second_pattern = self.cp.get('filter', 'second_pattern').decode('hex')
        self.reply_package = int(self.cp.get('filter', 'reply_package'))
        #deep filter value
        self.deep_split_block_pattern = self.cp.get('deep_filter', 'split_block_pattern').decode('hex')
        self.deep_block_count = int(self.cp.get('deep_filter', 'block_count')) + 1
        self.deep_filter_pattern = self.cp.get('deep_filter', 'filter_pattern').decode('hex')
        self.deep_filter_offset = int(self.cp.get('deep_filter', 'filter_offset'))
        #server count filter value
        self.server_count_first_offset = int(self.cp.get('server_count_filter', 'first_offset'))
        self.server_count_first_pattern = self.cp.get('server_count_filter', 'first_pattern').decode('hex')
        #client count filter value
        self.client_count_first_offset = int(self.cp.get('client_count_filter', 'first_offset'))
        self.client_count_first_pattern = self.cp.get('client_count_filter', 'first_pattern').decode('hex')
        #xml filter
        self.xml_block_name1 = self.cp.get('xml_filter', 'xml_block_name1').strip()
        self.xml_block_name2 = self.cp.get('xml_filter', 'xml_block_name2').strip()
        self.xml_block_name3 = self.cp.get('xml_filter', 'xml_block_name3').strip()

    def get_response_package_value(self):
        self.all_data = self.cp.get('response', 'all_data').decode('hex')
        #user define data can from package
        self.user_data_2_from_package = self.cp.get('response', 'user_data_2_from_package')
        self.user_data_2 = self.cp.get('response', 'user_data_2').decode('hex')
        self.user_data_2_pattern = self.cp.get('response', 'user_data_2_pattern').decode('hex')
        self.user_data_2_pattern_count = int(self.cp.get('response', 'user_data_2_pattern_count'))
        self.user_data_2_use_pattern = self.cp.get('response', 'user_data_2_use_pattern')

        self.copy_data_BB_use_pattern = self.cp.get('response', 'copy_data_bb_use_pattern')
        self.copy_data_BB_pattern = self.cp.get('response', 'copy_data_bb_pattern').decode('hex')
        self.copy_data_BB_pattern_count = int(self.cp.get('response', 'copy_data_bb_pattern_count'))
        self.copy_data_BB = self.cp.get('response', 'copy_data_bb').decode('hex')
        self.copy_data_BB_offset = int(self.cp.get('response', 'copy_data_bb_offset'))
        self.copy_data_BB_length = int(self.cp.get('response', 'copy_data_bb_length'))
        self.copy_data_CC_use_pattern = self.cp.get('response', 'copy_data_cc_use_pattern')
        self.copy_data_CC_pattern = self.cp.get('response', 'copy_data_cc_pattern').decode('hex')
        self.copy_data_CC_pattern_count = int(self.cp.get('response', 'copy_data_cc_pattern_count'))
        self.copy_data_CC = self.cp.get('response', 'copy_data_cc').decode('hex')
        self.copy_data_CC_offset = int(self.cp.get('response', 'copy_data_cc_offset'))
        self.copy_data_CC_length = int(self.cp.get('response', 'copy_data_cc_length'))
        self.copy_data_DD_use_pattern = self.cp.get('response', 'copy_data_dd_use_pattern')
        self.copy_data_DD_pattern = self.cp.get('response', 'copy_data_dd_pattern').decode('hex')
        self.copy_data_DD_pattern_count = int(self.cp.get('response', 'copy_data_dd_pattern_count'))
        self.copy_data_DD = self.cp.get('response', 'copy_data_dd').decode('hex')
        self.copy_data_DD_offset = int(self.cp.get('response', 'copy_data_dd_offset'))
        self.copy_data_DD_length = int(self.cp.get('response', 'copy_data_dd_length'))
        self.header_len = self.cp.get('response_len', 'header_length')
        self.invert_bytes = self.cp.get('response_len', 'invert_bytes')
        #deep filter response value
        self.deep_all_data = self.cp.get('deep_response', 'all_data').decode('hex')
        #user define data can from package
        self.deep_user_data_2_from_package = self.cp.get('deep_response', 'user_data_2_from_package')
        self.deep_user_data_2 = self.cp.get('deep_response', 'user_data_2').decode('hex')
        self.deep_user_data_2_pattern = self.cp.get('deep_response', 'user_data_2_pattern').decode('hex')
        self.deep_user_data_2_pattern_count = int(self.cp.get('deep_response', 'user_data_2_pattern_count'))
        self.deep_user_data_2_use_pattern = self.cp.get('deep_response', 'user_data_2_use_pattern')

        self.deep_copy_data_BB_use_pattern = self.cp.get('deep_response', 'copy_data_bb_use_pattern')
        self.deep_copy_data_BB_pattern = self.cp.get('deep_response', 'copy_data_bb_pattern').decode('hex')
        self.deep_copy_data_BB_pattern_count = int(self.cp.get('deep_response', 'copy_data_bb_pattern_count'))
        self.deep_copy_data_BB = self.cp.get('deep_response', 'copy_data_bb').decode('hex')
        self.deep_copy_data_BB_offset = int(self.cp.get('deep_response', 'copy_data_bb_offset'))
        self.deep_copy_data_BB_length = int(self.cp.get('deep_response', 'copy_data_bb_length'))
        self.deep_copy_data_CC_use_pattern = self.cp.get('deep_response', 'copy_data_cc_use_pattern')
        self.deep_copy_data_CC_pattern = self.cp.get('deep_response', 'copy_data_cc_pattern').decode('hex')
        self.deep_copy_data_CC_pattern_count = int(self.cp.get('deep_response', 'copy_data_cc_pattern_count'))
        self.deep_copy_data_CC = self.cp.get('deep_response', 'copy_data_cc').decode('hex')
        self.deep_copy_data_CC_offset = int(self.cp.get('deep_response', 'copy_data_cc_offset'))
        self.deep_copy_data_CC_length = int(self.cp.get('deep_response', 'copy_data_cc_length'))
        self.deep_copy_data_DD_use_pattern = self.cp.get('deep_response', 'copy_data_dd_use_pattern')
        self.deep_copy_data_DD_pattern = self.cp.get('deep_response', 'copy_data_dd_pattern').decode('hex')
        self.deep_copy_data_DD_pattern_count = int(self.cp.get('deep_response', 'copy_data_dd_pattern_count'))
        self.deep_copy_data_DD = self.cp.get('deep_response', 'copy_data_dd').decode('hex')
        self.deep_copy_data_DD_offset = int(self.cp.get('deep_response', 'copy_data_dd_offset'))
        self.deep_copy_data_DD_length = int(self.cp.get('deep_response', 'copy_data_dd_length'))
        #server count server data pattern
        self.copy_data_server_cc_use_pattern = self.cp.get('server_count_data', 'copy_data_server_cc_use_pattern')
        self.copy_data_server_cc_pattern = self.cp.get('server_count_data', 'copy_data_server_cc_pattern').decode('hex')
        self.copy_data_server_cc_pattern_count = int(self.cp.get('server_count_data', 'copy_data_server_cc_pattern_count'))
        self.copy_data_server_cc_length = int(self.cp.get('server_count_data', 'copy_data_server_cc_length'))
        self.copy_data_server_cc_offset = int(self.cp.get('server_count_data', 'copy_data_server_cc_offset'))
        #cleint count client data pattern
        self.copy_data_client_cc_use_pattern = self.cp.get('client_count_data', 'copy_data_client_cc_use_pattern')
        self.copy_data_client_cc_pattern = self.cp.get('client_count_data', 'copy_data_client_cc_pattern').decode('hex')
        self.copy_data_client_cc_pattern_count = int(self.cp.get('client_count_data', 'copy_data_client_cc_pattern_count'))
        self.copy_data_client_cc_length = int(self.cp.get('client_count_data', 'copy_data_client_cc_length'))
        self.copy_data_client_cc_offset = int(self.cp.get('client_count_data', 'copy_data_client_cc_offset'))
        #xml filter response value
        self.xml_all_data = self.cp.get('xml_response', 'all_data').decode('hex')
        #user define data can from package
        self.xml_user_data_2_from_package = self.cp.get('xml_response', 'user_data_2_from_package')
        self.xml_user_data_2 = self.cp.get('xml_response', 'user_data_2').decode('hex')
        self.xml_user_data_2_pattern = self.cp.get('xml_response', 'user_data_2_pattern').decode('hex')
        self.xml_user_data_2_pattern_count = int(self.cp.get('xml_response', 'user_data_2_pattern_count'))
        self.xml_user_data_2_use_pattern = self.cp.get('xml_response', 'user_data_2_use_pattern')

        self.xml_copy_data_BB_use_pattern = self.cp.get('xml_response', 'copy_data_bb_use_pattern')
        self.xml_copy_data_BB_pattern = self.cp.get('xml_response', 'copy_data_bb_pattern').decode('hex')
        self.xml_copy_data_BB_pattern_count = int(self.cp.get('xml_response', 'copy_data_bb_pattern_count'))
        self.xml_copy_data_BB = self.cp.get('xml_response', 'copy_data_bb').decode('hex')
        self.xml_copy_data_BB_offset = int(self.cp.get('xml_response', 'copy_data_bb_offset'))
        self.xml_copy_data_BB_length = int(self.cp.get('xml_response', 'copy_data_bb_length'))
        self.xml_copy_data_CC_use_pattern = self.cp.get('xml_response', 'copy_data_cc_use_pattern')
        self.xml_copy_data_CC_pattern = self.cp.get('xml_response', 'copy_data_cc_pattern').decode('hex')
        self.xml_copy_data_CC_pattern_count = int(self.cp.get('xml_response', 'copy_data_cc_pattern_count'))
        self.xml_copy_data_CC = self.cp.get('xml_response', 'copy_data_cc').decode('hex')
        self.xml_copy_data_CC_offset = int(self.cp.get('xml_response', 'copy_data_cc_offset'))
        self.xml_copy_data_CC_length = int(self.cp.get('xml_response', 'copy_data_cc_length'))
        self.xml_copy_data_DD_use_pattern = self.cp.get('xml_response', 'copy_data_dd_use_pattern')
        self.xml_copy_data_DD_pattern = self.cp.get('xml_response', 'copy_data_dd_pattern').decode('hex')
        self.xml_copy_data_DD_pattern_count = int(self.cp.get('xml_response', 'copy_data_dd_pattern_count'))
        self.xml_copy_data_DD = self.cp.get('xml_response', 'copy_data_dd').decode('hex')
        self.xml_copy_data_DD_offset = int(self.cp.get('xml_response', 'copy_data_dd_offset'))
        self.xml_copy_data_DD_length = int(self.cp.get('xml_response', 'copy_data_dd_length'))
        self.xml_copy_data_xml_block1 = self.cp.get('xml_response', 'xml_data_block1').decode('hex')
        self.xml_copy_data_xml_block2 = self.cp.get('xml_response', 'xml_data_block2').decode('hex')
        self.xml_copy_data_xml_block3 = self.cp.get('xml_response', 'xml_data_block3').decode('hex')

    def package_filter(self, data, cc_data=None, just_filter=False):
        data_length = len(data)
        #first make xml filter
        first_block = self.xml_search(data, self.xml_block_name1)
        seconds_block = self.xml_search(data, self.xml_block_name2)
        third_block = self.xml_search(data, self.xml_block_name3)
        if first_block is not None and seconds_block is not None and third_block is not None:
            if just_filter:
                return (None, XML_FILTER, None)
            else:
                resp_data_wl, data_BB = self.xml_response_data(data, cc_data, first_block, seconds_block, third_block)
                return (resp_data_wl, XML_FILTER, data_BB)

        if data_length < self.second_offset + 1:
                return (None, False, None)
        else:
            if data[self.first_offset] == self.first_pattern:
                if data[self.second_offset] == self.second_pattern:
                    deep_filter_data = self.data_parse(self.deep_split_block_pattern, 'yes', self.deep_block_count, self.deep_filter_offset, 1, data)
                    if deep_filter_data:
                        if deep_filter_data == self.deep_filter_pattern:
                            if just_filter:
                                return (None, DEEP_FILTER, None)
                            else:
                                resp_data_wl, data_BB =self.deep_response_data(data, cc_data)
                                return (resp_data_wl, DEEP_FILTER, data_BB)
                        else:
                            if just_filter:
                                return (None, FILTER, None)
                            else:
                                resp_data_wl, data_BB =self.response_data(data, cc_data)
                                return (resp_data_wl, FILTER, data_BB)
                    else:
                        if just_filter:
                            return (None, FILTER, None)
                        else:
                            resp_data_wl, data_BB =self.response_data(data, cc_data)
                            return (resp_data_wl, FILTER, data_BB)                  
                else:
                    return (None, False, None)
            else:
                return (None, False, None)

    def xml_search(self, data, block_name):
        block_tag = block_name.split('|')
        if len(block_tag) == 1:
            pattern = re.compile(r'<'+block_tag[0].strip()+'>([^<>&]+)</'+block_tag[0].strip()+'>', re.DOTALL)
        else:
            pattern = re.compile(r'<'+block_tag[0].strip()+'>.*<'+block_tag[1].strip()+'>([^<>&]+)</'+block_tag[1].strip()+'>.*</'+block_tag[0].strip()+'>', re.DOTALL)

        try:
            match = re.search(pattern, data)
            return match.group(1)
        except Exception, e:
            return None

    def package_counter_filter(self, data, just_filter=True):
        data_length = len(data)
        if data_length < self.server_count_first_offset + 1:
            return (None, False, None)

        if data[self.server_count_first_offset] == self.server_count_first_pattern:
            return (None, COUNTER_FILTER, None)

        return (None, False, None)



    def response_data(self, data, cc_data=None):
        copy_data_BB = self.data_parse(self.copy_data_BB_pattern, self.copy_data_BB_use_pattern,
            self.copy_data_BB_pattern_count, self.copy_data_BB_offset, 
            self.copy_data_BB_length, data)

        copy_data_CC = cc_data

        copy_data_DD = self.data_parse(self.copy_data_DD_pattern, self.copy_data_DD_use_pattern,
            self.copy_data_DD_pattern_count, self.copy_data_DD_offset, 
            self.copy_data_DD_length, data)
        
        if self.user_data_2_from_package == 'yes':
           user_data_2 = self.data_parse(self.user_data_2_pattern, self.user_data_2_use_pattern, self.user_data_2_pattern_count, None, None, data)
        else:
            user_data_2 = None

        response_data = self.response_data_gen(copy_data_BB, copy_data_CC, copy_data_DD, 
            self.copy_data_BB, self.copy_data_CC, self.copy_data_DD, user_data_2, self.user_data_2, self.all_data)
        return response_data, copy_data_BB

    def deep_response_data(self, data, cc_data=None):
        copy_data_BB = self.data_parse(self.deep_copy_data_BB_pattern, self.deep_copy_data_BB_use_pattern,
            self.deep_copy_data_BB_pattern_count, self.deep_copy_data_BB_offset, 
            self.deep_copy_data_BB_length, data)

        copy_data_CC = cc_data

        copy_data_DD = self.data_parse(self.deep_copy_data_DD_pattern, self.deep_copy_data_DD_use_pattern,
            self.deep_copy_data_DD_pattern_count, self.deep_copy_data_DD_offset, 
            self.deep_copy_data_DD_length, data)

        if self.deep_user_data_2_from_package == 'yes':
            user_data_2 = self.data_parse(self.deep_user_data_2_pattern, self.deep_user_data_2_use_pattern, 
                self.deep_user_data_2_pattern_count, None, None, data)
        else:
            user_data_2 = None

        response_data = self.response_data_gen(copy_data_BB, copy_data_CC, copy_data_DD, 
            self.deep_copy_data_BB, self.deep_copy_data_CC, self.deep_copy_data_DD, user_data_2, self.deep_user_data_2, self.deep_all_data)
        return response_data, copy_data_BB

    def xml_response_data(self, data, cc_data=None, xml_block1=None, xml_block2=None, xml_block3=None):
        copy_data_BB = self.data_parse(self.xml_copy_data_BB_pattern, self.xml_copy_data_BB_use_pattern,
            self.xml_copy_data_BB_pattern_count, self.xml_copy_data_BB_offset, 
            self.xml_copy_data_BB_length, data)

        copy_data_CC = cc_data

        copy_data_DD = self.data_parse(self.xml_copy_data_DD_pattern, self.xml_copy_data_DD_use_pattern,
            self.xml_copy_data_DD_pattern_count, self.xml_copy_data_DD_offset, 
            self.xml_copy_data_DD_length, data)

        if self.xml_user_data_2_from_package == 'yes':
            user_data_2 = self.data_parse(self.xml_user_data_2_pattern, self.xml_user_data_2_use_pattern, 
                self.xml_user_data_2_pattern_count, None, None, data)
        else:
            user_data_2 = None

        response_data = self.response_data_gen(copy_data_BB, copy_data_CC, copy_data_DD, 
            self.xml_copy_data_BB, self.xml_copy_data_CC, self.xml_copy_data_DD, user_data_2, self.xml_user_data_2, self.xml_all_data, 
            self.xml_copy_data_xml_block1, self.xml_copy_data_xml_block2, xml_block1, xml_block2, self.xml_copy_data_xml_block3, xml_block3)
        return response_data, copy_data_BB        

    def data_parse(self, pattern, use_pattern, count, offset, length, data):
        if offset is None:
            try:
                if use_pattern == 'yes':
                    copy_data = data.split(pattern)[count]
                    if copy_data == '':
                        copy_data = None
                    return copy_data
                else:
                    return None
            except Exception, e:
                return None
        else:
            try:
                if use_pattern == 'yes':
                    copy_data = data.split(pattern)[count]
                else:
                    copy_data = data
                copy_data_length = len(copy_data)
        
                end = offset + length
                copy_data_ret = copy_data[offset:end]
                return copy_data_ret
            except Exception, e:
                return None

    def response_data_gen(self, data_BB, data_CC, data_DD, conf_data_BB, conf_data_CC, 
            conf_data_DD, user_data_2, conf_user_data_2, all_resp_data, conf_xml_block1=None, conf_xml_block2=None, xml_block1=None, xml_block2=None,
            conf_xml_block3=None, xml_block3=None):
        if data_BB:
            response_data = all_resp_data.replace(conf_data_BB, data_BB)
        else:
            response_data = all_resp_data.replace(conf_data_BB, '')

        if data_CC:
            response_data = response_data.replace(conf_data_CC, data_CC)
        else:
            response_data = response_data.replace(conf_data_CC, '')

        if data_DD:
            response_data = response_data.replace(conf_data_DD, data_DD)
        else:
            response_data = response_data.replace(conf_data_DD, '')
        if user_data_2 is not None:
            response_data = response_data.replace(conf_user_data_2, user_data_2)

        if xml_block1:
            response_data = response_data.replace(conf_xml_block1, xml_block1)

        if xml_block2:
            response_data = response_data.replace(conf_xml_block2, xml_block2)

        if xml_block3:
            response_data = response_data.replace(conf_xml_block3, xml_block3)

        if self.header_len == '4':
            response_data_length = '%04d' % (len(response_data) - 4)
        else:
            if self.invert_bytes == 'yes':
                response_data_length = struct.pack('H', (len(response_data) - 4))
            else:
                response_data_length = struct.pack('!H', (len(response_data) - 4))
            
        response_data_with_length = response_data_length + response_data[4:]
        return response_data_with_length              


    def bytes_addone(self, bytes_data):
        if bytes_data.isdigit():
            if int(bytes_data) == 9999:
                re_data = '0001'
            else:
                re_data = '%04d' % (int(bytes_data) + 1)
        else:
            re_data = bytes_data
        return re_data

class SockRedirectServer(StreamServer):

    def __init__(self, listener, package_f, **kwargs):
        super(SockRedirectServer, self).__init__(listener, **kwargs)
        self.package_filter = package_f
        self.filter_db = shelve.open('/usr/local/share/filter_db', 'c')
        self.filter_tmp_db = shelve.open('/tmp/filter_tmp_db', 'c')
        self.reply_count = self.package_filter.reply_package
        self.server_filter = [0]
        file_fd = open('/tmp/package_filter/package_'+ str(time.time()), 'w+')
        self.save_filter_file = [file_fd]
        self.license = open('/usr/local/share/filter_active', 'r').readline().strip()
        self.save_filter_size = open('/usr/local/share/filter_size').readlines()[-1].split('=')[-1]
        #server count var
        self.server_counter_file = shelve.open('/usr/local/share/counter_file', 'c')
        #self.stime = time.time()

    def  init_socket(self):
        super(SockRedirectServer, self).init_socket()
        self.socket.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)

    def handle(self, source, address):
        #log('%s:%s accepted', *address[:2])
        try:
            orgi_dst = original_dst(source)
            source.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            source.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 10)
            source.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 10)
            #new kernel patch, not need set mac
            #mac = source.getsockopt(socket.IPPROTO_IP, 172, 14)

            if self.filter_db.has_key('count'):
                self.reply_count = self.filter_db['count']

            has_filtered = filter_db_get(self.filter_tmp_db, address[0], orgi_dst[0])
            filter_forward = FilterForward(source)

        except Exception as ex:
            log('%s:%s failed to connect to %s:%s: %s', address[0], address[1], orgi_dst[0], orgi_dst[1], ex)
            return            

        if has_filtered:
            filter_forward.forward_client(self, address, orgi_dst, has_filtered)
        else:
            forwarders = (gevent.spawn(filter_forward.forward_server, self, address, orgi_dst),
                gevent.spawn(filter_forward.forward_client, self, address, orgi_dst, False))
            gevent.joinall(forwarders)

    def close(self):
        if self.closed:
            sys.exit('Multiple exit signals received - aborting.')
        else:
            log('Closing listener socket')
            self.filter_db.close()
            StreamServer.close(self)

class FilterForward(object):
    
    def __init__(self, source):
        self.server_filter = False
        self.server_instance = None
        self.client_instance = None
        self.server_status = CONNECT_FAIL
        self.source =source
        self.dest = None
        self.has_filtered = False
        self.evt = Event()


    def forward_client(self, server, src_ip, dst_ip, has_filtered):


        drop_all = 0
        if has_filtered:
            drop_all = 1
            self.server_status =CONNECT_STOP
        else:
            if server.filter_tmp_db is not None:
                if filter_db_get(server.filter_tmp_db, src_ip[0], dst_ip[0]):
                    drop_all = 1
                    self.server_status =CONNECT_STOP
        #source_address = '%s:%s' % source.getpeername()[:2]
        #dest_address = '%s:%s' % dest.getpeername()[:2]
        reply_count = server.reply_count
        try:
            while True:
                try:
                    data = self.source.recv(1460)
                    #log('%s->%s: %r', source_address, dest_address, len(data))
                    if not data:
                        #log('client %s:%s is close session', src_ip[0], src_ip[1])
                        #remove client_instance, then retry connect to server will stop
                        self.server_status = CONNECT_STOP
                        break
                    #client side also need save counter file
                    response_data = server.package_filter.package_counter_filter(data, just_filter=True)
                    if response_data is not None :    
                        if response_data[1] == COUNTER_FILTER and server.package_filter.server_counter_side == 'no':
                                #creat counter_file from server side 
                                counter = server.package_filter.data_parse(server.package_filter.copy_data_client_cc_pattern, 
                                    server.package_filter.copy_data_client_cc_use_pattern, server.package_filter.copy_data_client_cc_pattern_count,
                                    server.package_filter.copy_data_client_cc_offset, server.package_filter.copy_data_client_cc_length, data)
                                if counter is not None:
                                    counter_file_create(server.server_counter_file, src_ip[0]+'_'+dst_ip[0]+'_'+str(dst_ip[1]), counter)
                                else:
                                    counter_file_create(server.server_counter_file, src_ip[0]+'_'+dst_ip[0]+'_'+str(dst_ip[1]), DEFAULT_COUNTER)

                    response_data = server.package_filter.package_filter(data, just_filter=True)
                    if response_data[1]:
                        #response is 2 do not set drop all and do not limit 20
                        if response_data[1] == FILTER:
                            if drop_all != 1:
                                #set server_filter value
                                self.server_filter = True
                                #set drop all tag
                                drop_all = 1
                            #if recv package no cc data we will copy from counter_file, if none is will be none
                            cc_data = server.package_filter.data_parse(server.package_filter.copy_data_CC_pattern, 
                                server.package_filter.copy_data_CC_use_pattern, server.package_filter.copy_data_CC_pattern_count, 
                                server.package_filter.copy_data_CC_offset, server.package_filter.copy_data_CC_length, data)
                            if cc_data is None:
                                cc_counter = counter_file_get(server.server_counter_file, src_ip[0]+'_'+dst_ip[0]+'_'+str(dst_ip[1]))
                                if cc_counter is None:
                                    cc_data = DEFAULT_COUNTER

                                else:
                                    #add one add save to file agin
                                    cc_data = server.package_filter.bytes_addone(cc_counter)

                                counter_file_create(server.server_counter_file, src_ip[0]+'_'+dst_ip[0]+'_'+str(dst_ip[1]), cc_data)
                            else:
                                cc_data = server.package_filter.bytes_addone(cc_data)

                            response_data = server.package_filter.package_filter(data, cc_data)
                            # count reply and if not 0 go filter and send filter package
                            if reply_count and server.license == 'yes':
                                if server.filter_tmp_db is not None:
                                    filter_db_create(server.filter_tmp_db, src_ip[0], dst_ip[0])
                                    server.filter_tmp_db.sync()
                                self.source.sendall(response_data[0])

                                #reply_count expr
                                reply_count = reply_count - 1
                                server.filter_db['count'] = reply_count
                                server.filter_db.sync()
                            #save  data and response to file
                            save_package_to_file(server.save_filter_file, reply_count, data, response_data, 
                                src_ip[0], dst_ip[0], response_data[2], server.save_filter_size)
                        elif response_data[1] == DEEP_FILTER:
                            if drop_all != 1:
                                #set server_filter value
                                self.server_filter = True
                                #set drop all tag
                                drop_all = 1
                            #if recv package no cc data we will copy from counter_file, if none is will be none
                            cc_data = server.package_filter.data_parse(server.package_filter.deep_copy_data_CC_pattern, 
                                server.package_filter.deep_copy_data_CC_use_pattern, server.package_filter.deep_copy_data_CC_pattern_count, 
                                server.package_filter.deep_copy_data_CC_offset, server.package_filter.deep_copy_data_CC_length, data)
                            if cc_data is None:
                                cc_counter = counter_file_get(server.server_counter_file, src_ip[0]+'_'+dst_ip[0]+'_'+str(dst_ip[1]))
                                if cc_counter is None:
                                    cc_data = DEFAULT_COUNTER
                                #add one add save to file agin
                                else:
                                    cc_data = server.package_filter.bytes_addone(cc_counter)
                                counter_file_create(server.server_counter_file, src_ip[0]+'_'+dst_ip[0]+'_'+str(dst_ip[1]), data)
                            else:
                                cc_data = server.package_filter.bytes_addone(cc_data)

                            response_data = server.package_filter.package_filter(data, cc_data)

                            if server.filter_tmp_db is not None:
                                filter_db_create(server.filter_tmp_db, src_ip[0], dst_ip[0])
                                server.filter_tmp_db.sync()                                
                            self.source.sendall(response_data[0])
                            #save data and response to file this set reply_count to 1 
                            # so response data always to save to file
                            save_package_to_file(server.save_filter_file, 1, data, response_data, 
                                src_ip[0], dst_ip[0], response_data[2], server.save_filter_size)
                        elif response_data[1] == XML_FILTER:
                            if drop_all != 1:
                                #set server_filter value
                                self.server_filter = True
                                #set drop all tag
                                drop_all = 1
                            #if recv package no cc data we will copy from counter_file, if none is will be none
                            cc_data = server.package_filter.data_parse(server.package_filter.xml_copy_data_CC_pattern, 
                                server.package_filter.xml_copy_data_CC_use_pattern, server.package_filter.xml_copy_data_CC_pattern_count, 
                                server.package_filter.xml_copy_data_CC_offset, server.package_filter.xml_copy_data_CC_length, data)
                            if cc_data is None:
                                cc_counter = counter_file_get(server.server_counter_file, src_ip[0]+'_'+dst_ip[0]+'_'+str(dst_ip[1]))
                                if cc_counter is None:
                                    cc_data = DEFAULT_COUNTER
                                #add one add save to file agin
                                else:
                                    cc_data = server.package_filter.bytes_addone(cc_counter)
                                counter_file_create(server.server_counter_file, src_ip[0]+'_'+dst_ip[0]+'_'+str(dst_ip[1]), data)
                            else:
                                cc_data = server.package_filter.bytes_addone(cc_data)

                            response_data = server.package_filter.package_filter(data, cc_data)

                            if server.filter_tmp_db is not None:
                                filter_db_create(server.filter_tmp_db, src_ip[0], dst_ip[0])
                                server.filter_tmp_db.sync()                                
                            self.source.sendall(response_data[0])

                    else:
                        self.evt.wait()
                        if self.server_status is CONNECTED and drop_all != 1:
                            try:
                                self.dest.sendall(data)
                            except socket.errno, arg:
                                (errno, err_msg) = arg
                                #log("server send data failed: %s, errno=%d", err_msg, errno)
                                #remove server instance and notifly retry connect in other gevent
                                self.dest.close()
                                self.server_status = CONNECT_FAIL
                                #sleep run ohter gevent first
                                gevent.sleep(0)
                                continue                                      
                except KeyboardInterrupt:
                    if not server.closed:
                        server.close()
                    break
                except socket.error, arg:
                    (errno, err_msg) = arg
                    log("client failed: %s, errno=%d", err_msg, errno)
                    break
        finally:
            self.source.close()
            self.server_status = CONNECT_STOP
            server = None

    def forward_server(self, server, src_ip, dst_ip):
        try:
            while True:
                try:
                    #accept client fast then try connect to server
                    #print 'server status ' + str(self.server_status)
                    if self.server_status is CONNECT_FAIL:
                        self.retry_connect(src_ip, dst_ip)
                    if self.server_status is CONNECT_STOP:
                        #log('client %s:%s close session, stop connect to server %s:%s', src_ip[0], src_ip[1], dst_ip[0], dst_ip[1])
                        break
                    if self.server_status is CONNECTED:
                        try:
                            data = self.dest.recv(1460)
                        except socket.error, arg:
                            (errno, err_msg) = arg
                            log("from client %s to server %s server recv data failed: %s, errno=%d", src_ip, dst_ip, err_msg, errno)
                            self.server_status= CONNECT_FAIL
                            continue  

                    #log('%s->%s: %r', source_address, dest_address, len(data))
                    if not data:
                        
                        # if server_side then retry connect and go on, remove server instance connect success add it agin
                        #log('server %s:%s is close session retry agin', dst_ip[0], dst_ip[1])
                        self.server_status = CONNECT_FAIL
                        continue

                    #server side if SERVER COUNT FILTER ok get cc data to file
                    response_data = server.package_filter.package_counter_filter(data, just_filter=True)
                    if response_data is not None:
                        if response_data[1] == COUNTER_FILTER and server.package_filter.server_counter_side == 'yes':
                            #creat counter_file from server side 
                            counter = server.package_filter.data_parse(server.package_filter.copy_data_server_cc_pattern, 
                                server.package_filter.copy_data_server_cc_use_pattern, server.package_filter.copy_data_server_cc_pattern_count,
                                server.package_filter.copy_data_server_cc_offset, server.package_filter.copy_data_server_cc_length, data)
                            if counter is not None:
                                counter_file_create(server.server_counter_file, src_ip[0]+'_'+dst_ip[0]+'_'+str(dst_ip[1]), counter)
                            else:
                                counter_file_create(server.server_counter_file, src_ip[0]+'_'+dst_ip[0]+'_'+str(dst_ip[1]), DEFAULT_COUNTER)
                            #save success then change mark to 0
                            #server_count[0] = 0 
                    if self.source is not None:
                        #server filter 
                        if self.server_filter is False:
                            try:
                                self.source.sendall(data)
                            except socket.errno, arg:
                                (errno, err_msg) = arg
                                #log("client send data failed: %s, errno=%d", err_msg, errno)
                                self.server_status = CONNECT_STOP
                                break              
                except KeyboardInterrupt:
                    if not server.closed:
                        server.close()
                    break
                except socket.error, arg:
                    (errno, err_msg) = arg
                    log("server failed: %s, errno=%d", err_msg, errno)
                    break
        finally:
            if self.dest is not None:
                self.dest.close()
                self.server_status = CONNECT_STOP
            server = None

    def retry_connect(self, src_ip, dst_ip):
        while True:
            try:
                if self.server_status is CONNECT_STOP:
                    break
                #log('retry connect to server %s:%s every one seconds', dst_ip[0], dst_ip[1])
                if self.dest is not None:
                    self.dest.close()
                self.dest = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                self.dest.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
                # new kernel patch, not need set mac
                #self.dest.setsockopt(socket.IPPROTO_IP, 172, self.dest_mac)
                self.dest.bind((src_ip[0], 0))
                self.dest.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self.dest.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 10)
                self.dest.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 10)
                self.dest.connect(dst_ip)
                log('connect server %s:%s success', dst_ip[0], dst_ip[1])
                self.server_status = CONNECTED
                self.evt.set()
                break
            except socket.error, arg:
                (errno, err_msg) = arg
                log("from client %s to server %s connect failed: %s, errno=%d", src_ip, dst_ip, err_msg, errno)
                #sleep 1s and try agin
                gevent.sleep(1)


def save_package_to_file(save_filter_file, reply_count, receive_data, response_data, src_ip, dst_ip, data_BB, save_filter_size):
    if data_BB is None:
        data_BB = '\xBB'
    save_filter_file[0].write('time: ' + time.ctime() + ' from client ip: ' + src_ip + 
        ' to server ip: ' + dst_ip + '\r\n' + ' data from block BB: ' + data_BB.encode('hex') + '\r\n')
    save_filter_file[0].write('receved data: ' + receive_data.encode('hex') + '\r\n')
    if reply_count:
        save_filter_file[0].write('response data: ' + response_data[0].encode('hex') + '\r\n')
    save_filter_file[0].flush()
    if save_filter_file[0].tell() >= long(save_filter_size):
        save_filter_file[0].close()
        file_fd = open('/tmp/package_filter/package_'+ str(time.time()), 'w+')
        save_filter_file[0] = file_fd    

def filter_db_create(db, key, value):
    if db.has_key(key):
        tmp_value = db[key]
        tmp_value.add(value)
        db[key] = tmp_value
    else: 
        db[key] = set([value])

def filter_db_get(db, key, value):
    if db.has_key(key):
        if value in db[key]:
            return True
        else:
            return False
    else:
            return False

def counter_file_create(counter_file, key, value):
    counter_file[key] = value
    counter_file.sync()

def counter_file_get(counter_file, key):
    if counter_file.has_key(key):
        return counter_file[key]
    else:
        return None
def original_dst(sock):
    return sock.getsockname()

def parse_address(address):
    try:
        hostname, port = address.rsplit(':', 1)
        port = int(port)
    except ValueError:
        sys.exit('Expected HOST:PORT: %r' % address)
    return gethostbyname(hostname), port


def main():
    package_f = PackageFilter('/etc/package_filter.conf')
    server = SockRedirectServer(('0.0.0.0',  10999), package_f)
    gevent.signal(signal.SIGTERM, server.close)
    gevent.signal(signal.SIGINT, server.close)
    server.serve_forever()
    gevent.wait()


def log(message, *args):
    message = message % args
    sys.stderr.write(message + '\n')


if __name__ == '__main__':
    main()
