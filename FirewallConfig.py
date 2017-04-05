"""This file handles various operations on an access list for a Cisco 3800-series router."""
"""import SVN"""
from Cisco import CiscoTelnetSession
import re
import sys
import os
import threading
import time
from datetime import datetime

class FirewallConfig(object):
	"""This class provides some simple operations for handling an access list for a Cisco 3800-series router."""

	#access-list 111 permit ip host 137.17.80.200 host 137.17.116.245
	#access-list 111 permit ip 137.17.80.0 0.0.0.255 host 137.17.116.245
	#https://github.com/vladak/aclcheck

	regex_whitespace = '\s*'
	regex_ip = '([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
	regex_netmask = '([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'	
	regex_port = '[0-9]{1,5}'
	regex_start_of_string = '^'
	regex_access_list = '(access-list [0-9]{1,3})'
	regex_permit_deny = '(permit|deny)'
	regex_protocol = '(gre|icmp|tcp|udp|esp|ip|[0-9]+)'
	regex_optionalport = '(range' + regex_whitespace + regex_port + regex_whitespace + regex_port + '|((eq|gt|lt)' + regex_whitespace + regex_port + '))?'
	regex_optionallog = '(log)?'
	regex_optionalestablished = '(established)?'
	regex_optionalreflect = '(reflect' + regex_whitespace + '[a-z]+)?'
	regex_end_of_string = '$'

	regex_host_net = '(host' + regex_whitespace + regex_ip + '|' + regex_ip + regex_whitespace + regex_netmask + '|any)'
	

	regex_firewall_line = [ regex_start_of_string, regex_access_list, regex_permit_deny, regex_protocol, regex_host_net, regex_optionalport, regex_host_net, regex_optionalport, regex_optionalreflect, regex_optionallog, regex_optionalestablished, regex_end_of_string ]

	def __init__(self):
		self.fd = None
		self.filename = None
		self.continue_checking = True
		self.last_check_time = datetime.fromtimestamp(1420070400)

	def set_filename(self, filename):
		self.filename = filename

	def open(self):
		self.fd = open(self.filename, 'r')
		

	def close(self):
		self.fd.close()

	def get_file_contents(self):
		self.open()
		contents = self.fd.read()
		self.close()
		return contents

	def start_editor(self):
		command = "" + self.filename
		#print "Starting '%s'" % command
		os.system(command)

	def check_file_once(self):
		file_valid = True
		self.open()
		for linenr,line in enumerate(self.fd.readlines()):
			file_valid = file_valid and self.check_line(FirewallConfig.regex_firewall_line, line, linenr)
		self.close()
		return file_valid


	def check_file_continously(self):
		file_mtime = datetime.fromtimestamp(os.path.getmtime(self.filename))
		if self.continue_checking:
			if file_mtime > self.last_check_time:
				self.check_file_once()
				self.last_check_time = file_mtime
			threading.Timer(1, self.check_file_continously).start()

	def stop_checking(self):
		self.continue_checking = False


	def check_regex(self, regex, line):
		search_result = re.search(regex, line)
		return search_result

	def construct_partial_regex(self, regex, count):
		regex_sublist = regex[:count]
		partial_regex = FirewallConfig.regex_whitespace.join(regex_sublist)
		return partial_regex

	def check_partial_regex(self, regex, line, count):
		partial_regex = self.construct_partial_regex(regex, count)
		line_matches = self.check_regex(partial_regex, line)
		return line_matches	

	def check_line_incrementally(self, regex, line, linenr):
		max_count = len(regex)
		max_valid_substring_length = 0
		for element_count in range(0, max_count+1):
			partial_check = self.check_partial_regex(regex, line, element_count)
			last_element = regex[element_count-1]

			if partial_check is not None:
				max_valid_substring_length = partial_check.end()
			else:
				error_lines = get_line_error(line, max_valid_substring_length, last_element, linenr)
				sys.stdout.write(error_lines)
				return False
		return True		

	def check_line(self, regex, line, linenr):
		if line[0] == '!' or len(line.strip()) == 0 or 'remark' in line or 'evaluate' in line:
			return True
		else:
			return self.check_line_incrementally(regex, line, linenr)


	def check_lines(self, regex, lines):
		search_results = []
		for linenr, line in enumerate(lines):
			line_result = self.check_line(regex, line, linenr)
			search_results.append(line_result)

def get_line_error(line, max_valid_substring_length, last_element, linenr):
		spaces = generate_spaces(max_valid_substring_length)
		ret = ""
		ret = ret + str(datetime.now()) + "\n"
		ret = ret + "Line " + str(1+linenr) + "\n"
		ret = ret + line + "\n"
		ret = ret + spaces + "^ \n"
		ret = ret + spaces + "Error at this position:\n"
		ret = ret + ("Can't match this pattern: '%s'\n" % last_element)
		return ret


def generate_spaces(count):
		ret = ""
		for counter in range(0, count):
			ret = ret + " "
		return ret




def file_get_contents(filename):
	with open(filename) as f:
		ret = f.read()
	return ret




if __name__ == '__main__':
	if len(sys.argv) < 3:
		sys.stderr.write("Usage: " + sys.argv[0] + " username password")
		sys.exit(-1)

	hostname = "llf-router-venus.dnw.aero"
	telnet_port = 23
	username = str(sys.argv[1])
	password = str(sys.argv[2])
	header = file_get_contents("header.access-list")
	footer = file_get_contents("footer.access-list")

	fwc = FirewallConfig()
	fwc.set_filename("test.access-list")
	fwc.check_file_continously()
	fwc.start_editor()
	fwc.stop_checking()

	print("Editing finished, checking file one last time")
	if fwc.check_file_once():
		print("File appears valid...")
		print("SVN commit")
		"""SVN.svn_commit()"""
		print("Constructing final router text...")
		contents = fwc.get_file_contents()
		configure_command = header + '\n' + contents + '\n' + footer

		print("Connecting to router...")
		session = CiscoTelnetSession()
		if not session.open(hostname, telnet_port, username, password):
			sys.stderr.write("Error connecting to: " + hostname + ":" + str(telnet_port))
			sys.exit(-1)
		print("Configuring firewall...")
		print("---")
		print(configure_command)
		print("---")
		output = session.execute_command(configure_command)
	#	print "Output:"
	#	print "---"
	#	print output
	#	print "---"

	#raw_input("Press any key to end program...")
