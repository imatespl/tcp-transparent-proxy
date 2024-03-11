#!/usr/bin/env python
#-*-coding: utf-8-*-
# Copyright (c) 2016 dwliu. See LICENSE for details.

import socket, sys, signal, gevent, ConfigParser, struct, time, shelve
from gevent.server import StreamServer
from gevent.socket import create_connection, gethostbyname
from gevent import monkey
monkey.patch_socket()
try:
    from socket import IP_TRANSPARENT
except ImportError:
    IP_TRANSPARENT = 19
 
class PackageFilter(object):
 
    def __init__(self, config):
        self.cp = ConfigParser.SafeConfigParser()
        self.cp.read(config)
        self.get_filter_value()
        self.get_response_package_value()
 
    def get_filter_value(self):
        self.first_offset = int(self.cp.get('filter', 'first_offset'))
        self.first_pattern = self.cp.get('filter', 'first_pattern').decode('hex')
        self.second_offset = int(self.cp.get('filter', 'second_offset'))
        self.second_pattern = self.cp.get('filter', 'second_pattern').decode('hex')
        self.reply_package = int(self.cp.get('filter', 'reply_package'))
 
    def get_response_package_value(self):
        self.all_data = self.cp.get('response', 'all_data').decode('hex')
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
        self.header_len = self.cp.get('response', 'header_length')
 
    def package_filter(self, data):
        data_length = len(data)
        if data_length < self.second_offset + 1:
            return False
        if data[self.first_offset] == self.first_pattern:
            if data[self.second_offset] == self.second_pattern:
                if self.copy_data_BB_use_pattern == 'yes':
                    BB_data = data.split(self.copy_data_BB_pattern)[self.copy_data_BB_pattern_count]
                else:
                    BB_data = data
                BB_data_length = len(BB_data)
                BB_start = self.copy_data_BB_offset
                if BB_start == 0:
                    BB_end = self.copy_data_BB_offset + self.copy_data_BB_length + 1
                else:
                    BB_end = self.copy_data_BB_offset + self.copy_data_BB_length
                if BB_data_length > BB_end:
                    copy_data_BB = BB_data[BB_start:BB_end]
                elif BB_data_length > BB_start and BB_data_length <= BB_end:
                    copy_data_BB = BB_data[BB_start:]
                if self.copy_data_CC_use_pattern == 'yes':
                    CC_data = data.split(self.copy_data_CC_pattern)[self.copy_data_CC_pattern_count]
                else:
                    CC_data = data
                CC_data_length = len(CC_data)
                CC_start = self.copy_data_CC_offset
                if CC_start == 0:
                    CC_end = self.copy_data_CC_offset + self.copy_data_CC_length + 1
                else:
                    CC_end = self.copy_data_CC_offset + self.copy_data_CC_length
                if CC_data_length > CC_end:
                    copy_data_CC = CC_data[CC_start:CC_end]
                elif CC_data_length > CC_start and CC_data_length <= CC_end:
                    copy_data_CC = CC_data[CC_start:]
                if self.copy_data_DD_use_pattern == 'yes':
                    DD_data = data.split(self.copy_data_DD_pattern)[self.copy_data_DD_pattern_count]
                else:
                    DD_data = data
                DD_data_length = len(DD_data)
                DD_start = self.copy_data_DD_offset
                if DD_start == 0:
                    DD_end = self.copy_data_DD_offset + self.copy_data_DD_length + 1
                else:
                    DD_end = self.copy_data_DD_offset + self.copy_data_DD_length
                if DD_data_length > DD_end:
                    copy_data_DD = DD_data[DD_start:DD_end]
                elif DD_data_length > DD_start and DD_data_length <= DD_end:
                    copy_data_DD = DD_data[DD_start:]
                if copy_data_BB:
                    response_data = self.all_data.replace(self.copy_data_BB, copy_data_BB)
                else:
                    response_data = self.all_data.replace(self.copy_data_BB, '')
                if copy_data_CC:
                    copy_data_CC_addone = self.bytes_addone(copy_data_CC)
                    response_data = response_data.replace(self.copy_data_CC, copy_data_CC_addone)
                else:
                    response_data = response_data.replace(self.copy_data_CC, '')
                if copy_data_DD:
                    response_data = response_data.replace(self.copy_data_DD, copy_data_DD)
                else:
                    response_data = response_data.replace(self.copy_data_DD, '')
                if self.header_len == '4':
                    response_data_length = '%04d' % (len(response_data) - 4)
                else:
                    response_data_length = struct.pack('!H', len(response_data) - 4)
                response_data_with_length = response_data_length + response_data[4:]
                return response_data_with_length
            else:
                return False
 
        else:
            return False
 
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
        self.package_f = package_f
        self.filter_db = shelve.open('/usr/local/share/filter_db', 'c')
        self.reply_count = self.package_f.reply_package
 
    def init_socket(self):
        super(SockRedirectServer, self).init_socket()
        self.socket.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
 
    def handle(self, source, address):
        try:
            orgi_dst = original_dst(source)
            source.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            source.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 10)
            source.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 10)
            mac = source.getsockopt(socket.IPPROTO_IP, 172, 14)
            if self.filter_db.has_key('count'):
                self.reply_count = self.filter_db['count']
            has_filtered = filter_db_get(self.filter_db, address[0], orgi_dst[0])
            if has_filtered is False:
                dest = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dest.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
                dest.setsockopt(socket.IPPROTO_IP, 172, mac)
                dest.bind((address[0], address[1]))
                dest.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                dest.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 10)
                dest.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 10)
                dest.connect(orgi_dst)
        except IOError as ex:
            return
 
        if has_filtered:
            filter_forward(source, None, self, self.package_f.package_filter, self.filter_db, address[0], orgi_dst[0], has_filtered, self.reply_count)
        else:
            forwarders = (
             gevent.spawn(filter_forward, source, dest, self, self.package_f.package_filter, self.filter_db, address[0], orgi_dst[0], False, self.reply_count),
             gevent.spawn(filter_forward, dest, source, self))
            gevent.joinall(forwarders)
        return
 
    def close(self):
        if self.closed:
            sys.exit('Multiple exit signals received - aborting.')
        else:
            log('Closing listener socket')
            self.filter_db.close()
            StreamServer.close(self)
 
 
def filter_forward(source, dest=None, server=None, package_filter=None, filter_db=None, src_ip=None, dst_ip=None, has_filtered=False, reply_count=None):
    drop_all = 0
    if has_filtered:
        drop_all = 1
    elif filter_db is not None:
        if filter_db_get(filter_db, src_ip, dst_ip):
            drop_all = 1
    try:
        while True:
            try:
                data = source.recv(1460)
                if drop_all != 1:
                    if not data:
                        break
                    if package_filter is not None:
                        if reply_count:
                            response_data = package_filter(data)
                            if response_data:
                                if filter_db is not None:
                                    filter_db_create(filter_db, src_ip, dst_ip)
                                source.sendall(response_data)
                                drop_all = 1
                                reply_count = reply_count - 1
                                filter_db['count'] = reply_count
                                filter_db.sync()
                            elif dest is not None:
                                dest.sendall(data)
                    elif dest is not None:
                        dest.sendall(data)
                elif drop_all == 1:
                    if not data:
                        break
                    if package_filter is not None:
                        if reply_count:
                            response_data = package_filter(data)
                            if response_data:
                                source.sendall(response_data)
                                reply_count = reply_count - 1
                                filter_db['count'] = reply_count
                                filter_db.sync()
            except KeyboardInterrupt:
                if not server.closed:
                    server.close()
                break
            except socket.error:
                break
 
    finally:
        source.close()
        if dest is not None:
            dest.close()
        server = None
 
    return
 
 
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
 
 
def original_dst(sock):
    return sock.getsockname()
 
 
def parse_address(address):
    try:
        hostname, port = address.rsplit(':', 1)
        port = int(port)
    except ValueError:
        sys.exit('Expected HOST:PORT: %r' % address)
 
    return (
     gethostbyname(hostname), port)
 
 
def main():
    package_f = PackageFilter('/etc/package_filter.conf')
    server = SockRedirectServer(('0.0.0.0', 10999), package_f)
    gevent.signal(signal.SIGTERM, server.close)
    gevent.signal(signal.SIGINT, server.close)
    server.serve_forever()
    gevent.wait()
 
 
def log(message, *args):
    message = message % args
    sys.stderr.write(message + '\n')
 
 
if __name__ == '__main__':
    main()