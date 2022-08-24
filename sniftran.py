#!/usr/bin/env python2.7

# BSD 3-Clause License
# 
# Copyright (c) 2015 - 2022, Ondrej Holecek <ondrej at holecek dot eu>
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# 
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# 
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#
# Program to translate text packet sniffer outputs collected on Forti* devices,
# see "-h" for more information.
# 

import re
import collections
import binascii
import datetime
import struct
import getopt
import sys
import time
import os
import random

class DataSource_File:
	def __init__(self, filename):
		self.sourcefile = open(filename, "r")

		# save the size of the file
		try:
			self.sourcefile.seek(0, os.SEEK_END)
			self.sourcefile_size = self.sourcefile.tell()
			self.sourcefile.seek(0, os.SEEK_SET)
		except IOError:
			# can happen when reading from stdin or fifo, etc.
			self.sourcefile_size = 0
			pass

	def getSize(self):
		return self.sourcefile_size

	def readline(self):
		return self.sourcefile.readline()


class PacketParser:

	def __init__(self, datasource, compatible=True):
		# compile regular expressions
		if compatible:
			#without fac:
			#self.packetLine = re.compile("(^[0-9a-f]*\t)|(^0x[0-9a-f]* )")
			#self.packetLineParser = re.compile("^(0x)?([0-9a-f]*)[\t ]*([0-9a-f ]*)[ \t][ \t]*")
			# with FAC with "tcpdump -XXe -tt -s0 -ni port1 port not 22"
			self.packetLine = re.compile("(^[0-9a-f]*\t)|(^0x[0-9a-f]*[ \t:])")
			self.packetLineParser = re.compile("^(0x)?([0-9a-f]*)[\t :]*([0-9a-f ]*)[ \t][ \t]*")
		else:
			self.packetLine = re.compile("^0x[0-9a-f]{4}[ \t]")
			self.packetLineParser = re.compile("^(0x)([0-9a-f]{4})[ \t]*([0-9a-f ]*)[ \t][ \t]*")

		#self.headerLineTimeAbsolute = re.compile("^([0-9]{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)\.([0-9]*) ")
		#self.headerLineTimeRelative = re.compile("^([0-9]*)\.([0-9]*)[ \t]")
		# 20220823: recognize 6k7k prefix
		self.headerLineTimeAbsolute = re.compile("^(?:\[(.*)\s*\]\s+)?([0-9]{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)\.([0-9]*) ")
		self.headerLineTimeRelative = re.compile("^(?:\[(.*)\s*\]\s+)?([0-9]*)\.([0-9]*)[ \t]")
		self.headerLineIface = re.compile("^([^ ]*) ([^ ]*) ")

		self.ds = datasource
		self.sourcefile_size = self.ds.getSize()

		self.wholefile = collections.deque(maxlen = 500)

		self.debug_linesRead = 0
		self.debug_bytesRead = 0

	def getNextLine(self):
		while True:
			line = self.ds.readline()
			if len(line) == 0: raise Exception("end of file")
			self.debug_linesRead += 1
			self.debug_bytesRead += len(line)
			line = line.strip()
			if len(line) == 0: continue  # ignore empty lines

			self.wholefile.append(line)
			break
	
		return line

	def getLine(self, history=0):
		i = len(self.wholefile)-1-history
		while True:
			line = self.wholefile[i]
			if len(line) != 0: break
			i -= 1
		return line

	def normalizePacketLine(self, line):
		newline = line
		x = line.split()
		last = x[-1]
		if len(last) > 16:
			newline = line[:-len(last)] + last[:(len(last)-16)] + " " + last[(len(last)-16):]

		return newline

	def parsePacketLine(self, line):
		if normalize_lines: line = self.normalizePacketLine(line)
		g = self.packetLineParser.search(line)
		if not g: raise Exception("unparsable line: %s" % (line,))

		linePosition = int(g.group(2), 16)
		hexBytes = g.group(3).replace(" ", "")
		binBytes = binascii.unhexlify(hexBytes)

		return (linePosition, binBytes)
		
	def getPacketLine(self):
		while True:
			line = self.getNextLine()
			#print line, (self.packetLine.search(line))
			if not (self.packetLine.search(line)): continue

			(linePosition, binBytes) = self.parsePacketLine(line)
			if len(binBytes) == 0: continue

			break

		if linePosition == 0: 
			additional = self.parseHeaderLine(self.getLine(history=1)) + (self.debug_linesRead,)
		else:
			additional = ()

		return (linePosition, binBytes, additional)

	def parseHeaderLine(self, line):
		ts = 0
		slot = None # for chassis 6k7k
		iface = "unknown"
		direction = "unknown"

		# first parse data&time
		while True:
			g = self.headerLineTimeAbsolute.search(line)
			if g:
				slot = g.group(1)
				year = int(g.group(2))
				month = int(g.group(3))
				day = int(g.group(4))
				hour = int(g.group(5))
				minute = int(g.group(6))
				second = int(g.group(7))
				msec = int(g.group(8))

				line = line[len(g.group(0)):]
	
				dt = datetime.datetime(year, month, day, hour, minute, second, msec)
				#ts = int(dt.strftime("%s"))
				# the above expression does not work on Windows :(
				ts = int(time.mktime(dt.timetuple()))        
				us = int(dt.strftime("%f")) # is this right? or us = float(dt.strftime("0.%f")) ?
				break # to prevent the next check

			g = self.headerLineTimeRelative.search(line)
			if g:
				line = line[len(g.group(0)):]

				slot = g.group(1)
				ts = int(g.group(2))
				us = int(g.group(3))
				break

			# if we've exhausted all options...
			print "WARNING: cannot recognize time format"
			break

		# then find the interface and direction
		while True:
			g = self.headerLineIface.search(line)
			if g:
				iface = g.group(1)
				direction = g.group(2)
				line = line[len(g.group(0)):]
				break # to prevent the next (possible) check 

			# if we've exhausted all options...
			print "WARNING: cannot recognize interface and/or direction format"
			break

		# if this is 6k7k blade, prefix interface with blade name
		if slot != None:
			iface = slot + "/" + iface

		#print (ts, us, iface, direction)
		return (ts, us, iface, direction)

class PacketAssembler:

	def __init__(self, packetparser):
		self.pp = packetparser
		self.packetLines = collections.deque()
		self.packets = collections.deque()

	# Reads as many lines as it is necessary to assemble the full packet
	# Returns: "True" if the packet is not last, "False" if there are no more packets to read
	def assemblePacket(self):
		EOF = False

		while True:
			try:
				(offset, content, additional) = self.pp.getPacketLine()
			except Exception, e:
				if str(e) == "end of file": EOF = True
				else: 
					print "WARNING: packet decoder problem occurred on line %i, packet ignored" % (self.pp.debug_linesRead)
					if stop_on_error: raise

			if EOF or (offset == 0):  # extract the old packet
				if len(self.packetLines) > 0: 
					packetLength = self.packetLines[-1][0] + len(self.packetLines[-1][1])
					binaryPacket = bytearray(packetLength)
					additionalInfo = ()
	
					while len(self.packetLines) > 0:
						(c_offset, c_content, c_additional) = self.packetLines.popleft()
						if c_offset == 0: additionalInfo = c_additional # additional information is only in the first line of the packet
						binaryPacket[c_offset:c_offset+len(c_content)] = c_content
	
					self.packets.append( (binaryPacket, additionalInfo) )
					if not EOF: self.packetLines.append( (offset, content, additional) )
					break

			if not EOF: self.packetLines.append( (offset, content, additional) )
			if EOF: break
		
		if EOF: return False
		else: return True


	def getPacketsCount(self):
		return len(self.packets)
			
	def getPacket(self):
		return self.packets.popleft()

class PcapNGWriter:
	def __init__(self, outfile, max_in_file = None):
		self.max_in_file = max_in_file

		# split file name, in case we need to have more than one files
		if output_file[-7:] == '.pcapng': 
			self.output_file_base = output_file[:-7]
			self.output_file_suffix = '.pcapng'
		else:
			self.output_file_base = output_file
			self.output_file_suffix = ''

		# open the file with the original filename, it can be renamed in the future
		self.f_current = "%s%s" % (self.output_file_base, self.output_file_suffix)
		self.f = open(self.f_current, "wb")
		self.f_packet_count = 0
		self.f_file_count = 1

	def writePackets(self, blockIfaces, blockPackets):

		options = self.blockOption(4, "SnifTran ($Revision: 33 $) by Ondrej Holecek")   # application name
		options += self.blockEndOfOptions()

		packet_index = 0
		while len(blockPackets[packet_index:]) > 0:  # when we still have packets to save...
			if self.max_in_file == None:
				# when amount of packets in file is unlimited, we have as many slots as we need
				slots_free = len(blockPackets[packet_index:])
				if debug >= 2: print "DEBUG: amount of packets in file is unlimited, packets to save: %i, file already contains: %i, free slots: %i" % (
				                     len(blockPackets[packet_index:]), self.f_packet_count, slots_free,)
			else:
				# otherwise we need to be more cautious
				slots_free = self.max_in_file - self.f_packet_count
				if debug >= 2: print "DEBUG: amount of packets in file is limited to %i, packets to save: %i, file already contains: %i, free slots current cycle: %i" % (
				                     self.max_in_file, len(blockPackets[packet_index:]), self.f_packet_count, slots_free,)

			if slots_free == 0:
				# we need to write packets, but there are not slots in the file
				# so we need to open another file
				self.f.close()

				if self.f_file_count == 1: # if this was the first, original, file, rename it to the split format
					newname = "%s.part%03i%s" % (self.output_file_base, 1, self.output_file_suffix)
					if debug >= 1: print "DEBUG: renaming original output file '%s' to '%s'" % (self.f_current, newname,)
					os.rename(self.f_current, newname)

				self.f_file_count += 1
				self.f_current = "%s.part%03i%s" % (self.output_file_base, self.f_file_count, self.output_file_suffix)
				if debug >= 1: print "DEBUG: opening new output file '%s'" % (self.f_current,)
				self.f = open(self.f_current, "wb")

				# reset the packet count as we have a new file
				self.f_packet_count = 0
				slots_free = self.max_in_file - self.f_packet_count

			# write packets to available slots
			data = blockIfaces + bytearray().join(blockPackets[packet_index:packet_index+slots_free])

			block = struct.pack(">I", 0x0A0D0D0A)
			block += struct.pack(">I", 28+len(options))
			block += struct.pack(">I", 0x1A2B3C4D)
			block += struct.pack(">HH", 1, 0)
			block += struct.pack(">q", -1)  # section length
			block += options;
			block += struct.pack(">I", 28+len(options))
			block += data

			self.f.write(block)
			self.f_packet_count += len(blockPackets[packet_index:packet_index+slots_free])
			if debug >= 3: print "DEBUG: written %i packets, %i bytes to the current output file, now the file contains: %i" % (len(blockPackets[packet_index:packet_index+slots_free]), len(block), self.f_packet_count)

			packet_index += len(blockPackets[packet_index:packet_index+slots_free])

	
	LINKTYPE_ETHERNET = 1;
	LINKTYPE_PPP = 9;
	LINKTYPE_RAW = 101;
	LINKTYPE_NULL = 0;
	def blockInterfaceDescription(self, iface, linktype, tsresol=6):

		options = self.blockOption(2, iface)   # interface name
		options += self.blockOption(9, chr(tsresol) ) # timestamp resolution, default 6 means microseconds
		options += self.blockEndOfOptions()

		block = struct.pack(">I", 0x00000001)
		block += struct.pack(">I", 20+len(options))
		block += struct.pack(">H", linktype)  # linktype
		block += struct.pack(">H", 0)  # reserved
		block += struct.pack(">i", -1) # snaplen (max possible lenght of captured packet)
		block += options
		block += struct.pack(">I", 20+len(options))

		#print "interface block length:", len(block), ", reported length:", 20+len(options)
		return block
	
	def blockEnhancedPacket(self, packet, timestamp, ifaceIndex, comment=""):

		options = self.blockOption(1, comment)
		options += self.blockEndOfOptions()

		packetPad = 0
		if (len(packet) % 4) > 0: packetPad = 4-(len(packet) % 4)

		block = struct.pack(">I", 0x00000006)        # block type
		block += struct.pack(">I", 32+len(packet)+packetPad+len(options))
		block += struct.pack(">I", ifaceIndex)  # interface id
		block += struct.pack(">Q", timestamp)  # timestamp 64bit (in format docs this is shown as two 32bit numbers)
		block += struct.pack(">I", len(packet))  # capture length
		block += struct.pack(">I", len(packet))  # packet length
		block += packet
		for i in range(packetPad): block += struct.pack(">b", 0)
		block += options
		block += struct.pack(">I", 32+len(packet)+packetPad+len(options))

		#print "packet length:", len(packet), "padding:", packetPad, "reported:", 32+len(packet)+packetPad+len(options), "real:", len(block)

		return block
	
	def blockOption(self, code, value):
		valuePad = 0
		if len(value) % 4 > 0: valuePad = 4-(len(value) % 4)

		block = struct.pack(">H", code)
		block += struct.pack(">H", len(value))
		block += value
		for i in range(valuePad): block += struct.pack(">b", 0)
		return block

	def blockEndOfOptions(self):
		block = struct.pack(">H", 0)
		block += struct.pack(">H", 0)
		return block

### 
class IPSec:
	def __init__(self, sourcefile):
		self.sourcefile = sourcefile
		self.tunnels = {}

		self.cipher_map = { 
		                    ("aes", "16") : "AES-CBC [RFC3602]",
                        }

		self.hash_map = {
		                    ("sha1", "20") : "HMAC-SHA-1-96 [RFC2404]",
		                }

		if 'HOME' in os.environ:
			self.wireshark_config = "%s/.wireshark/esp_sa" % (os.environ['HOME'],)
		elif 'APPDATA' in os.environ:
			self.wireshark_config = "%s/Wireshark/esp_sa" % (os.environ['APPDATA'],)
		else:
			self.wireshark_config = None
			if debug >= 1:
				print "DEBUG: unknown wireshark esp config file, ignoring"
	
	def find_tunnels(self):
		if not self.wireshark_config: return

		fd = open(self.sourcefile, "r")
		current = None
		
		fd_readBytes = 0
		# save the size
		try:
			fd.seek(0, os.SEEK_END)
			fd_size = fd.tell()
			fd.seek(0, os.SEEK_SET)
		except IOError:
			# can happen for fifo etc.
			# but in that case this whole part would not work anyway
			fd_size = 0


		while True:
			line = fd.readline()
			if len(line) == 0: break
			fd_readBytes += len(line)
			line = line.strip()
			ls = line.split()
		
			if len(ls) >= 1 and  "name=" in ls[0][:5] and ls[1] == "ver=1":
				current = ls[0][5:]
				while current in self.tunnels:
					# different phase1s can have the phase2s with the same name
					# - if it happens, just rename it
					newcurrent = "%s_%i" % (current, random.random()*1000,)
					current = newcurrent
		
				self.tunnels[current] = {}
				self.tunnels[current]['src'] = ls[3].split("->")[0].split(":")[0]
				self.tunnels[current]['dst'] = ls[3].split("->")[1].split(":")[0]
			
			if len(ls) >= 1 and ls[0] in ("dec:", "enc:"):
				direction = ls[0][:3]
		
				# first line is encryption
				if "spi=" != ls[1][:4]:
					print "WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown line format (spi)" % (direction, current,)
					self.tunnels[current]['ignore'] = True
				else:
					spi = ls[1][4:]
		
				if "esp=" != ls[2][:4]:
					print "WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown line format (esp)\n" % (direction, current,)
					self.tunnels[current]['ignore'] = True
				else:
					esp = ls[2][4:]
		
				if "key=" != ls[3][:4]:
					print "WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown line format (keylength)\n" % (direction, current,)
					self.tunnels[current]['ignore'] = True
				else:
					keylength = ls[3][4:]
		
				try:
					key = ls[4]
				except:
					print "WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown line format (key)\n" % (direction, current,)
					self.tunnels[current]['ignore'] = True
		
				# next line should be authentication
				auth = fd.readline().strip().split()
				if "ah=" != auth[0][:3]:
					print "WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown line format (ah)\n" % (direction, current,)
					self.tunnels[current]['ignore'] = True
				else:
					authalg = auth[0][3:]
		
				if "key=" != auth[1][:4]:
					print "WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown line format (authkeylength)\n" % (direction, current,)
					self.tunnels[current]['ignore'] = True
				else:
					authkeylength = auth[1][4:]
			
				try:
					authkey = auth[2]
				except:
					print "WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown line format (authkey)\n" % (direction, current,)
					self.tunnels[current]['ignore'] = True
		
				self.tunnels[current][direction] = {}
				self.tunnels[current][direction]["spi"] = spi
				self.tunnels[current][direction]["alg"] = esp
				self.tunnels[current][direction]["keylength"] = keylength
				self.tunnels[current][direction]["key"] = key
				self.tunnels[current][direction]["authalg"] = authalg
				self.tunnels[current][direction]["authkeylength"] = authkeylength
				self.tunnels[current][direction]["authkey"] = authkey


			if show_progress:
				progress_current = fd_readBytes * 100 / fd_size
				if 'progress_last' not in vars(): progress_last = None
				if progress_current != progress_last:
					sys.stdout.write("PROGRESS: ipsec: %3i %%\r" % (progress_current,))
					sys.stdout.flush()
					progress_last = progress_current

		fd.close()

	def configure_wireshark(self):
		outfile = self.wireshark_config
		if not outfile: return

		for tunnel in self.tunnels.keys():
			if 'ignore' in self.tunnels[tunnel] and self.tunnels[tunnel]['ignore']:
				# there was something wrong with this tunnel...
				continue

			for direction in ("enc", "dec",):
				# cyphers
				cipher = (self.tunnels[tunnel][direction]['alg'], self.tunnels[tunnel][direction]['keylength'])
				if cipher not in self.cipher_map:
					print "WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown cipher (%s, %s)\n" % (direction, tunnel, cipher[0], cipher[1],)
					continue
				else:
					ws_alg = self.cipher_map[cipher]
		
				# hashes
				hashish = (self.tunnels[tunnel][direction]['authalg'], self.tunnels[tunnel][direction]['authkeylength'])
				if hashish not in self.hash_map:
					print "WARNING: ignoring \"%s\" direction for tunnel \"%s\" because of unknown hash (%s, %s)\n" % (direction, tunnel, hashish[0], hashish[1],)
					continue
				else:
					ws_authalg = self.hash_map[hashish]

				# we need to use the right direction, otherwise wireshark would not recognize it	
				if direction == 'enc':
					dirpart = '"%s","%s"' % (self.tunnels[tunnel]['src'], self.tunnels[tunnel]['dst'],)
				elif direction == 'dec':
					dirpart = '"%s","%s"' % (self.tunnels[tunnel]['dst'], self.tunnels[tunnel]['src'],)
				else:
					dirpart = "error_that_never_happens"
					
				outfd = open(outfile, "a")
				outfd.write('"IPv4",%s,"0x%s","%s","0x%s","%s","0x%s"\n' % (
					dirpart,
					self.tunnels[tunnel][direction]['spi'],
					ws_alg,
					self.tunnels[tunnel][direction]['key'],
					ws_authalg,
					self.tunnels[tunnel][direction]['authkey'],
					))
				outfd.close()

###
def usage():
	message = "\n"
	message += "===\n"
	message += "=== SnifTran - written by Ondrej Holecek <ondrej@holecek.eu>\n"
	message += "===\n"
	message += "\n"
	message += "usage: %s --in <inputfile> [optional_parameters...]\n" % (sys.argv[0],)
	message += "\n"
	message += "   mandatory parameters:\n"
	message += "    --in <inputfile>                   ... text file with captured packets, \"-in\" can be used for compatability\n"
	message += "\n"
	message += "   optional parameters:\n"
	message += "    --out <outputfile>                 ... name of the output pcap file, by default <inputfile>.pcapng\n"
	message += "    --no-overwrite                     ... do not overwrite the output file if it already exists\n"
	message += "    --no-compat                        ... disable the compatability with new FE and FAC sniffers outputs\n"
	message += "    --skip <number>                    ... skip first <number> packets\n"
	message += "    --limit <number>                   ... save only <number> packets\n"
	message += "    --no-checks                        ... disable packet integrity checks\n"
	message += "    --no-normalize-lines               ... do not try to normalize packet lines before parsing them\n"
	message += "    --no-wireshark-ipsec               ... do not update Wireshark config file with found IPSec tunnels\n"
	message += "    --include <interface>              ... save only packets from/to this interface (can be used multiple times)\n"
	message += "    --exclude <interface>              ... ignore packets from/to this interface (can be used multiple times)\n"
	message += "    --p2p <interface>                  ... mark interface as point-to-point, will try to correctly remove artifical ethernet header\n"
	message += "    --nolink <interface>               ... for this interface, do not expect any link layer information (for sniffer with parameter 5)\n"
	message += "\n"
	message += "   pcapng parameters:\n"
	message += "    --section-size <number>            ... amount if packets in one SHB, default unlimited (Wireshark does not support anything else!)\n"
	                                                       # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12167
	message += "    --max-packets <count>              ... maximum amount of packets in one pcapng file, writes multiple files if neceesary\n"
	message += "\n"
	message += "   debug options:\n"
	message += "    --debug <level>                    ... enable debug on specified level (1 - ?)\n"
	message += "    --show-packets                     ... prints binary content of each packet and additional info (timestamp, interface, ...)\n"
	message += "    --show-timestamps                  ... for performance test, show timestamp before each main operation block\n"
	message += "    --stop-on-error                    ... raise an exception when packet parsing error occurres\n"
	message += "    --include-packet-line              ... inserts the first line in the original file where the packet was found\n"
	message += "    --progress                         ... show progress when parsing and assembling packets, be aware of small speed penalty\n"
	message += "\n"
	message += "notes:\n"
	message += "   FortiGate           - \"diagnose sniffer packet ...\" must be run with level 6\n"
	message += "                       - if there are issues with considering also non-packet lines, disable FE & FAC compatibility mode\n"
	message += "   FortiMail           - with compatibility mode (default) even the new format is recognized\n"
	message += "   FortiAuthenticator  - command to collect packets must be \"tcpdump -XXe -s0 -tt -ni <interface> <filter>...\"\n"
	message += "\n"
	sys.stderr.write(message)



input_file = None
output_file = None
overwrite = True
compat_mode = True
skip_packets = 0
limit_packets = None
check_packet_size = True
interfaces_include = set()
interfaces_exclude = set()
interfaces_ptp = set()
interfaces_nolink = set()

section_size = None  # Wireshark currently does not support multiple sections
max_packets_in_file = None

debug = 0
show_packets = False
show_timestamps = False
normalize_lines = True
wireshark_ipsec = True
stop_on_error = False
include_packet_line = False
show_progress = False

def readOptions():
	# mark global variable
	global input_file
	global output_file
	global overwrite
	global compat_mode
	global skip_packets
	global limit_packets
	global check_packet_size
	global interfaces_include
	global interfaces_exclude
	global interfaces_ptp
	global interfaces_nolink
	global section_size
	global max_packets_in_file
	global debug
	global show_packets
	global show_timestamps
	global normalize_lines
	global wireshark_ipsec
	global stop_on_error
	global include_packet_line
	global show_progress

	# be backwards compatible with the old "fgt2eth.pl"
	for i in range(1, len(sys.argv)):
		if sys.argv[i] == "-in": sys.argv[i] = "--in"

	paramsStartFrom = 1
	# the first paramenter can be just plaintext file name without any -/-- before
	if len(sys.argv) > 1 and len(sys.argv[paramsStartFrom]) > 0 and sys.argv[paramsStartFrom][0] != "-":
		input_file = sys.argv[paramsStartFrom]
		paramsStartFrom += 1

	# first get options from user
	try:
		opts, args = getopt.getopt(sys.argv[paramsStartFrom:], "h", 
		             ["help", "in=", "out=", "no-overwrite", "no-compat", "skip=", "limit=", "no-checks", "include=", "exclude=", "p2p=", "nolink=", "no-normalize-lines",
						  "section-size=", "max-packets=",
						  "no-wireshark-ipsec",
						  "debug=", "show-packets", "show-timestamps", "stop-on-error", "include-packet-line", "progress"])
	except getopt.GetoptError as err:
		print str(err) # will print something like "option -a not recognized"
		usage()
		sys.exit(1)

	for o, a in opts:
		if o in ("-h", "--help"):
			usage()
			sys.exit(1)
		elif o in ("--in",):
			input_file = a
		elif o in ("--out",):
			output_file = a
		elif o in ("--no-overwrite",):
			overwrite = False
		elif o in ("--no-compat",):
			compat_mode = False
		elif o in ("--skip",):
			skip_packets = int(a)
		elif o in ("--limit",):
			limit_packets = int(a)
		elif o in ("--no-checks",):
			check_packet_size = False
		elif o in ("--include",):
			interfaces_include.add(a)
		elif o in ("--exclude",):
			interfaces_exclude.add(a)
		elif o in ("--p2p",):
			interfaces_ptp.add(a)
		elif o in ("--nolink",):
			interfaces_nolink.add(a)
		elif o in ("--section-size",):
			section_size = int(a)
		elif o in ("--max-packets",):
			max_packets_in_file = int(a)
		elif o in ("--debug",):
			debug = int(a)
		elif o in ("--show-packets",):
			show_packets = True
		elif o in ("--show-timestamps",):
			show_timestamps = True
		elif o in ("--no-normalize-lines",):
			normalize_lines = False
		elif o in ("--no-wireshark-ipsec",):
			wireshark_ipsec = False
		elif o in ("--stop-on-error",):
			stop_on_error = True
		elif o in ("--include-packet-line",):
			include_packet_line = True
		elif o in ("--progress",):
			show_progress = True
		else:
			assert False, "unhandled option"

	# configure some additional defaults
	if not output_file: output_file = "%s.pcapng" % (input_file,)
	
	# make sure all required parameters are present and correct
	if not input_file: 
		sys.stderr.write("ERROR: mandatory \"--in\" parameter is missing\n")
		usage()
		sys.exit(2)

	# check the existence of the output file
	exists = True
	try: open(output_file, "r")
	except IOError: exists = False

	if exists and not overwrite:
		sys.stderr.write("ERROR: output file \"%s\" already exists, and --no-overwrite parameter was used\n" % (output_file,))
		sys.exit(3)
	
	# if debug is enabled, show all parameters that we use
	if debug >= 1:
		print "DEBUG: SnifTran version: $Id: sniftran.py 33 2016-05-04 09:03:15Z oholecek $"
		print "DEBUG: parameters in use:"
		print "DEBUG:   input file: %s" % (input_file,)
		print "DEBUG:   output file: %s" % (output_file,)
		print "DEBUG:   allow output file overwrite: %s" % (overwrite,)
		print "DEBUG:   FE and FAD compatibility mode: %s" % (compat_mode,)
		print "DEBUG:   skip packets: %i" % (skip_packets,)
		if limit_packets: print "DEBUG:   limit packets: %i" % (limit_packets,)
		else: print "DEBUG:   limit packets: unlimited"
		print "DEBUG:   integrity checks: \"packet size\"=%s" % (check_packet_size,)
		print "DEBUG:   normalize lines: %s" % (normalize_lines,)
		print "DEBUG:   include interfaces: \"%s\"" % ("\", \"".join(interfaces_include),)
		print "DEBUG:   exclude interfaces: \"%s\"" % ("\", \"".join(interfaces_exclude),)
		print "DEBUG:   p2p interfaces: \"%s\"" % ("\", \"".join(interfaces_ptp),)
		print "DEBUG:   nolink interfaces: \"%s\"" % ("\", \"".join(interfaces_nolink),)
		if section_size: print "DEBUG:   section size: %i" % (section_size,)
		else: print "DEBUG:   section size: unlimited"
		if max_packets_in_file: print "DEBUG:   max packets in file: %i" % (max_packets_in_file,)
		else: print "DEBUG:   max packets in file: unlimited"
		print "DEBUG:   debug level: %i" % (debug,)
		print "DEBUG:   show packets: %s" % (show_packets,)
		print "DEBUG:   show timestamps: %s" % (show_timestamps,)
		print "DEBUG:   process ipsec for wireshark: %s" % (wireshark_ipsec,)
		print "DEBUG:   stop on error: %s" % (stop_on_error,)
		print "DEBUG:   include packet line: %s" % (include_packet_line,)
		print "DEBUG:   show progress: %s" % (show_progress,)


def process():
	#timestamp_start = int (datetime.datetime.now().strftime("%s"))
	# the above expression does not work on Windows :(
	timestamp_start = int(time.mktime(datetime.datetime.now().timetuple()))
	if show_timestamps: print "DEBUG: processing started at %i, referred as T" % (timestamp_start,)

	ds = DataSource_File(input_file)

	pp = PacketParser(datasource = ds, compatible=compat_mode)
	pc = PacketAssembler(packetparser = pp)
	pcap = PcapNGWriter(outfile = output_file, max_in_file = max_packets_in_file)
	
	
	ifaces_blocks = {}   # holds reusable block of interfaces - key is the index in pcap
	ifaces_block = ""
	ifaces = set() # holds all known interfaces
	
	packets_assembled = 0
	packets_read = 0
	packets_formated = 0
	
	while True:
		eof = False
	
		# first assemble preconfigured amount of packets
		if debug >= 2: print "DEBUG: assembling packets from input file"
		if show_timestamps: 
			timestart_start_assembling = int(time.mktime(datetime.datetime.now().timetuple()))
			print "DEBUG: assembling started at %i, T+%i" % (timestart_start_assembling, timestart_start_assembling-timestamp_start)

		packets_assembled_in_section = 0
		while True:
			if section_size and (packets_assembled_in_section >= section_size): break
	
			eof = not pc.assemblePacket()
			packets_assembled += 1
			packets_assembled_in_section += 1
			if (debug >= 3) and (packets_assembled % 10000 == 0): print "DEBUG: assembled %i packets" % (packets_assembled,)

			# display progress if requested
			if show_progress and packets_assembled % 1000 == 0: 
				progress_current = pp.debug_bytesRead * 100 / pp.sourcefile_size
				if 'progress_last' not in vars(): progress_last = None
				if progress_current != progress_last:
					sys.stdout.write("PROGRESS: assembling: %3i %%\r" % (pp.debug_bytesRead * 100 / pp.sourcefile_size))
					sys.stdout.flush()
					progress_last = progress_current
	
			if eof: break
		if debug >= 2: print "DEBUG: assembled %i packets totally, %i in current section" % (packets_assembled, packets_assembled_in_section,)
		
		# then go through all of them, and
		# - extract the interface name (to see whenther we need to define a new iface in pcap)
		# - move packet to the local list called "packets"
		current_ifaces = set()  # holds a set of interfaces used in this part of the capture
		binary_packets = []
	
		if debug >= 2: print "DEBUG: reading packets"
		if show_timestamps: 
			timestart_start_reading = int(time.mktime(datetime.datetime.now().timetuple()))
			print "DEBUG: reading started at %i, T+%i" % (timestart_start_reading, timestart_start_reading-timestamp_start)

		packets_read_in_section = 0
		while True:
			try:
				(packetBytes, additionalInfo) = pc.getPacket()
			except IndexError:
				break

			try:
				iface = additionalInfo[2]
				if (len(interfaces_include) > 0) and (iface not in interfaces_include): continue
				if (len(interfaces_exclude) > 0) and (iface in interfaces_exclude): continue
				current_ifaces.add(iface)
				timestamp = additionalInfo[0] * 1000000 + additionalInfo[1]  # convert seconds and useconds to one large us number
				comment = "(%s)%s%s" % (additionalInfo[3], " "*(4-len(additionalInfo[3])), additionalInfo[2],) # comment contains the direction of the packet and the interface
				if include_packet_line: comment += "  %5i" % (additionalInfo[4],)
				binary_packets.append( (iface, timestamp, comment, packetBytes,) )
				packets_read += 1
				packets_read_in_section += 1
				if (debug >= 3) and (packets_read % 10000 == 0): print "DEBUG: prepared %i packets" % (packets_read,)
			except IndexError:
				print "WARNING: invalid data for packet %i, ignoring" % (packets_read+1,)
				continue

		if debug >= 2: print "DEBUG: read packets %i totally, %i in current section" % (packets_read, packets_read_in_section,)
	
		if debug >= 2: print "DEBUG: looking for yet unknown interfaces"
		if show_timestamps: 
			timestart_start_interfaces = int(time.mktime(datetime.datetime.now().timetuple()))
			print "DEBUG: interfaces lookup started at %i, T+%i" % (timestart_start_interfaces, timestart_start_interfaces-timestamp_start)

		# for new interfaces, create a pcap interface block
		for new_iface in (current_ifaces-ifaces):
			new_index = len(ifaces_blocks)
			iface_type = pcap.LINKTYPE_ETHERNET

			# if this interface is marked as point-to-point, make it also in pcap interface description
			if new_iface in interfaces_ptp:
				iface_type = pcap.LINKTYPE_NULL

			# if this interface is marked as nolink, do not modify the packet, but mark as RAW (layer 3)
			if new_iface in interfaces_nolink:
				iface_type = pcap.LINKTYPE_RAW

			ifaces_blocks[new_iface] = { 'index' : new_index, 'block' : pcap.blockInterfaceDescription(new_iface, iface_type) }
			if debug >= 3: print "DEBUG: new iface found: \"%s\", assigning index %i" % (new_iface, ifaces_blocks[new_iface]['index'],)
		if debug >= 2: print "DEBUG: found %i new interfaces" % (len(current_ifaces-ifaces),)
	
		# if the amount of interfaces has changed, rebuild the block
		if len(current_ifaces - ifaces) > 0:
			if debug >= 2: print "DEBUG: rebuilding interfaces block"
			for iface in sorted(ifaces_blocks, key=lambda x: ifaces_blocks[x]['index']):
				#print "new interface: ", iface, ifaces_blocks[iface]
				ifaces_block += ifaces_blocks[iface]['block']
	
		ifaces |= current_ifaces   # copy new interfaces to known ifaces
	
		# prepare the packets block
		if debug >= 2: print "DEBUG: formating packets"
		if show_timestamps: 
			timestart_start_formating = int(time.mktime(datetime.datetime.now().timetuple()))
			print "DEBUG: packet formating started at %i, T+%i" % (timestart_start_formating, timestart_start_formating-timestamp_start)

		packets_formated_in_section = 0
		ignore_packets = 0
		blockPackets = []
		for i in range(skip_packets, len(binary_packets)):
			(iface_name, timestamp, comment, packetBytes) = binary_packets[i]
			if show_packets: print "DEBUG: packet: iface=\"%s\", timestamp=\"%s\", comment=\"%s\", binary: \"%s\"" % (
			                       iface_name, timestamp, comment, binascii.hexlify(packetBytes))

			# if this interface is marked as point-to-point, remove artificial ethernet header
			if iface_name in interfaces_ptp:
				packetBytes = packetBytes[10:]  # remove 6 bytes for src and 6 byte for dst MAC, keep 2 byte protocol ("ethertype") 
				packetBytes[0] = 0              # however,  because LINKTYPE_NULL is used as L2 and it needs first 4 bytes for protocl
				packetBytes[1] = 0              # we need to prepend another 2 bytes (0x0) to ethertype
	
			# if allowed, check whether the packet has the right size
			# - currently only IPv4 over ethernet is supported
			if check_packet_size:
				ethertype = "0x%02x%02x" % (packetBytes[12], packetBytes[13],)
				if ethertype == "0x0800": 
					totallength = int("0x%02x%02x" % (packetBytes[16], packetBytes[17],), 16)
					if totallength+14 > len(packetBytes):
						print "WARNING: packet #%i is not complete, ignoring" % (packets_formated+1,)
						if debug >= 3: print "DEBUG: packet size from IP header %i, (%i including ethernet) total packet size %i" % (totallength, totallength+14, len(packetBytes),)
						ignore_packets = 1
	
			if ignore_packets > 0:
				ignore_packets -= 1
			else:
				blockPackets.append(pcap.blockEnhancedPacket(packetBytes, timestamp=timestamp, ifaceIndex=ifaces_blocks[iface_name]['index'], comment=comment))
	
			packets_formated += 1
			packets_formated_in_section += 1
			if (debug >= 3) and (packets_formated % 10000 == 0): print "DEBUG: formated %i packets" % (packets_formated,)

			if show_progress and packets_formated % 1000 == 0:
				progress_current = i * 100 / len(binary_packets)
				if 'progress_last' not in vars(): progress_last = None
				if progress_current != progress_last:
					sys.stdout.write("PROGRESS: formating: %3i %%\r" % (progress_current,))
					sys.stdout.flush()
					progress_last = progress_current

			if limit_packets and (packets_formated >= limit_packets): break
		if debug >= 2: print "DEBUG: formated %i packets totally, %i in current section" % (packets_formated, packets_formated_in_section,)
	
		# now create a new section with interfaces and the packets we have collected in this block
		if debug >= 2: print "DEBUG: saving current section into the output file"
		if show_timestamps: 
			timestart_start_saving = int(time.mktime(datetime.datetime.now().timetuple()))
			print "DEBUG: packet saving started at %i, T+%i" % (timestart_start_saving, timestart_start_saving-timestamp_start)

		pcap.writePackets(ifaces_block, blockPackets)
	
		# if that was the last packet, we can finish here
		if eof: break

	# if wireshark SA check is enabled
	if wireshark_ipsec:
		if show_timestamps: 
			timestart_start_ipsec = int(time.mktime(datetime.datetime.now().timetuple()))
			print "DEBUG: ipsec SA lookup started at %i, T+%i" % (timestart_start_ipsec, timestart_start_ipsec-timestamp_start)

		ipsec = IPSec(sourcefile = input_file)
		ipsec.find_tunnels()
		ipsec.configure_wireshark()

	if show_timestamps: 
		timestart_done = int(time.mktime(datetime.datetime.now().timetuple()))
		print "DEBUG: finally done at %i, T+%i" % (timestart_done, timestart_done-timestamp_start)



### MAIN ###

readOptions()
process()

