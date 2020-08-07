#!/usr/bin/env python

import sys
import os
import time
import argparse
import socket
from multiprocessing.pool import ThreadPool

import requests
from requests.packages import urllib3
from requests.exceptions import ProxyError, TooManyRedirects, ConnectionError, ConnectTimeout, ReadTimeout

import logging
from logging.handlers import RotatingFileHandler


class WorkersConfig:
	""" Workers configurations """
	WORKERS_COUNT = 10  # How many threads will make http requests.
	DECREMENTED_COUNT_ON_ERROR = int(-(-(WORKERS_COUNT/10) // 1))  # Retry the fuzzing with x less workers, to decrease the load on the server.


class LogConfig:
	"""	Logging configurations. """
	FORMAT = '%(asctime)s - %(levelname)s - [%(name)s] - %(message)s'
	# LEVEL = os.environ.get("LOGLEVEL", "INFO")
	LEVEL = logging.INFO
	FOLDER = 'logs'
	FILES_COUNT = 50
	MAX_BYTES = 0.5 * 1000 * 1000  # 500 KB
	INTERVAL = 100  # Every x started jobs, a log will be written
	LOGGER_NAME = 'sdf'


class IoConfig:
	""" IO Configurations """
	DEFAULT_PATHS_LIST_FILE = './pathlists/general/test.txt'
	VALID_ENDPOINTS_FILE = 'endpoints.txt'


class HttpConfig:
	""" HTTP Configuration """
	# ACCEPT_STATUS_CODES = list(range(200, 300)) + [401, 402, 403]
	ACCEPT_STATUS_CODES = [200]
	ACCEPT_SCHEMAS = ['http','https']
	USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36'
	TIMEOUT = 5
	DELAY = 0.03


class Config:
	"""Aggregate all configs into one."""

	def __init__(self):
		self.http = HttpConfig()
		self.workers = WorkersConfig()
		self.log = LogConfig()
		self.io = IoConfig()


if __name__ == '__main__':
	config = Config()


class LoggerFactory(object):
	"""
	Manages loggers
	"""

	loggers = {}
	logging.basicConfig(stream=sys.stdout, level=config.log.LEVEL, format=config.log.FORMAT)

	@staticmethod
	def get_logger(logger_name):
		"""
		Gets a logger by it's name. Created the logger if it don't exist yet.
		:param logger_name: The name of the logger (identifier).
		:return: The logger instance.
		:returns: Logger
		"""
		if logger_name not in LoggerFactory.loggers:
			LoggerFactory.loggers[logger_name] = LoggerFactory._get_logger(logger_name)
		return LoggerFactory.loggers[logger_name]

	@staticmethod
	def _get_logger(logger_name, logs_directory_path=config.log.FOLDER):
		"""
		Creates a logger with rolling file handler,
		Or returns the logger if it already exists.
		:param logger_name: The name of the logger
		:param logs_directory_path: The path of the directory that the logs will be written to.
		:return: An initialized logger instance.
		returns: Logger
		"""
		# Creating the logs folder if its doesn't exist
		if not os.path.exists(logs_directory_path):
			os.mkdir(logs_directory_path)

		logger = logging.getLogger(logger_name)
		formatter = logging.Formatter(config.log.FORMAT)

		# Adding a rotating file handler
		rotating_file_handler = RotatingFileHandler(
			os.path.join(logs_directory_path, '{0}.log'.format(logger_name)), 
			maxBytes=config.log.MAX_BYTES,
			backupCount=config.log.FILES_COUNT
		)
		rotating_file_handler.setFormatter(formatter)
		rotating_file_handler.setLevel(config.log.LEVEL)
		logger.addHandler(rotating_file_handler)

		return logger

class UrlFactory:
	def scheme_check(self, url):
		parsed = urllib3.util.parse_url(url)
		if (parsed.scheme is not None and parsed.scheme in config.http.ACCEPT_SCHEMAS):
			return {'scheme':parsed.scheme, 'host':parsed.host}
		return {'scheme':'https', 'host':parsed.host}


	def make_subdomains(self, url, subdomains):
		url = self.scheme_check(url)
		resulted_list = []
		resulted_list += [url['scheme']+'://'+url['host']]
		for s in subdomains:
			resulted_list.append(url['scheme']+'://'+s+'.'+url['host'])
		return resulted_list
			



class FilesFactory(object):
	"""Manage files and directories"""
	files = []
	urls = []

	def read_files_from_directory(self, user_path):
		self.files = [os.path.join(user_path, f) for f in os.listdir(user_path) if os.path.isfile(os.path.join(user_path, f))]

	def read_lines_from_files(self):
		for l in self.files:
			h = open(l, 'r')
			self.urls += h.read().splitlines()

	def __init__(self, user_path):
		if os.path.isdir(user_path):
			self.read_files_from_directory(user_path)
			self.read_lines_from_files()
		elif os.path.isfile(user_path):
			self.files.append(user_path)
			self.read_lines_from_files()


class AsyncURLFuzzer(object):

	def __init__(self,
				base_url,
				list_file=config.io.DEFAULT_PATHS_LIST_FILE,
				async_workers_count=config.workers.WORKERS_COUNT,
				output_file=config.io.VALID_ENDPOINTS_FILE,
				resource_exists_status_codes=config.http.ACCEPT_STATUS_CODES
		):
		self.logger = LoggerFactory.get_logger(config.log.LOGGER_NAME)
		self.list_file = list_file
		self.async_workers_count = async_workers_count
		self.base_url = base_url
		self.output_file = output_file
		self.resource_exists_status_codes = resource_exists_status_codes
		self.active_paths_status_codes = {}
		self.checked_endpoints = {}
		self.endpoints_total_count = 0
		self.session = requests.session()
		self.session.headers['User-Agent'] = config.http.USER_AGENT

	def start(self):
		url_parsed = urllib3.util.parse_url(self.base_url)
		if (url_parsed.scheme is None):
			self.base_url = 'https://'+self.base_url
		url_parsed = urllib3.util.parse_url(self.base_url)
		if (url_parsed.scheme not in config.http.ACCEPT_SCHEMAS):
			self.logger.info('Wrong scheme "'+url_parsed.scheme+'" at "'+url_parsed.host+'"')
			return None
		if url_parsed.scheme=='https': 
			port = 443 
		else: 
			port = 80
		if self._check_host(url_parsed.host, url_parsed.scheme) is None: 
			self._save_output_log()
			return None
		self._get_website_endpoints()

	def _check_host(self, url, scheme):
		self.logger.info('>>> Check: '+scheme+'://'+url)
		session = requests.session()
		session.headers['User-Agent'] = config.http.USER_AGENT
		try:
			responce = session.head(scheme+'://'+url, verify=False, allow_redirects=False, timeout=config.http.TIMEOUT)
			if responce.status_code not in config.http.ACCEPT_STATUS_CODES:
				self.logger.info('URL code is ['+str(responce.status_code)+'], skip!')
				responce.close()
				return None
		except ConnectionError as e:
			self.logger.info('URL ConnectionError, skip!')
			session.close()
			return None

		responce.close()
		return True


	def _get_website_endpoints(self, async_workers_count=config.workers.WORKERS_COUNT):
		"""
		Requests asynchronously for all the resources with a number of workers (threads).
		If it fails for HTTP overloads reasons, it retries with less workers, because it's probably a DDOS
		protection mechanism.
		:param async_workers_count: How many workers (threads) to use.
		:type async_workers_count: int
		"""
		self._load_paths_files() # fill path_files_list

		if 0 >= async_workers_count:
			self.logger.info('Seems like the site ['+ self.base_url +'] does not support fuzzing, as it has a DDOS protection engine.')
			return

		pool = ThreadPool(async_workers_count)
		try:
			tasks = []
			self.logger.info('>>> Preparing the workers for ['+self.base_url+']...')
			for i, paths_file in enumerate(self.path_files_list):
				self.logger.debug('Load: '+paths_file)
				self.list_file = paths_file
				self._load_paths_list() # fill self.paths with one file strings
				
				self.logger.info('Proceed tasks from: '+paths_file)
				# make tasks from self.paths lines
				for i, path in enumerate(self.paths):
					self.logger.debug('Started a worker for the endpoint /{0}'.format(path))
					if i > i and i % config.log.INTERVAL == 0:
						self.logger.info('Started {0} workers'.format(i))
					path = path.strip()
					full_path = '/'.join([self.base_url, path])
					tasks.append(pool.apply_async(self.request_head, (full_path, path))) # set task
			

				for t in tasks:
					task_result = t.get()
					
					if task_result is not None:
						status_code, full_path, path = t.get() # get task result
						self.checked_endpoints[path] = path
					
						if status_code in self.resource_exists_status_codes:
							self.active_paths_status_codes[path] = status_code
							self.logger.debug('Fetched {0}/{1}; {2}; {3}'.format(
								len(self.checked_endpoints), self.endpoints_total_count, status_code, full_path
							))
				self._save_output_log()
		except requests.ConnectionError as e:
			pool.terminate()
			self.logger.debug('Error! Code: {c}, Message, {m}'.format(c = type(e).__name__, m = str(e)))
			self.logger.info('An error occurred while fuzzing. Retrying with less async workers to reduce the server load.')
			retry_workers_count = async_workers_count - config.workers.DECREMENTED_COUNT_ON_ERROR
			self._get_website_endpoints(retry_workers_count)


	def _save_output_log(self):
		"""
		Saves the results to an output file.
		"""
		full_status_codes = {'/'.join([self.base_url, p]): code for p, code in self.active_paths_status_codes.items()}
		# output_lines = ['{0} : {1}'.format(path, code) for path, code in full_status_codes.items()]
		output_lines = ['{0}'.format(path) for path, code in full_status_codes.items()]
		if len(output_lines) <= 0:
			self.logger.info('No endpoints for [' + self.base_url + ']')
		else:
			self.logger.info('The following endpoints are active:{0}{1}'.format(os.linesep, os.linesep.join(output_lines))+"\n\n")
			with open(self.output_file, 'a+') as output_file:
				output_lines.sort()
				output_file.write(os.linesep.join(output_lines))
				output_file.write(os.linesep)
			self.logger.debug('The endpoints were exported to "{0}"'.format(self.output_file)+"\n\n")


	def _load_paths_files(self):
		path_files_list = []
		list_file = self.list_file.strip().rstrip('/')
		if os.path.isdir(list_file):
			for root, dirs, files in os.walk(list_file):
				path = root.split(os.sep)
				for file in files:
					if file=='.DS_Store': continue
					path_files_list += [os.sep.join(path+[file])]
			
		else:
			path_files_list = [list_file]
		self.path_files_list = path_files_list

	def _load_paths_list(self):
		"""
		Loads the list of paths from the configured status.
		"""
		if not os.path.exists(self.list_file):
			self.logger.info('The file "{0}" does not exist.'.format(self.list_file))
			raise FileNotFoundError('The file "{0}" does not exist.'.format(self.list_file))
		with open(self.list_file, 'r') as paths_file:
			paths = [p.strip().lstrip('/').rstrip('/') for p in paths_file.read().splitlines()]
			paths = [p for p in paths if p not in self.active_paths_status_codes] # check if path already fuzzed
			if not self.endpoints_total_count:
				self.endpoints_total_count = len(paths)
			self.paths = paths

	def request_head(self, url, path):
		"""
		Executes a http HEAD request to a url.
		:param url: The full url to contact.
		:param path: The uri of the request.
		:return: A tuple of 3 variables:
			the received status code (int),
			the url argument (str),
			the path argument (str).
		"""
		self.logger.debug('Request: ' + url)
		if url != '':
			try:
				if config.http.DELAY!=0:
					time.sleep(config.http.DELAY)
				res = self.session.head(url, verify=False, allow_redirects=False, timeout=config.http.TIMEOUT)
			except ReadTimeout as e:
				self.logger.info('Timeout error: '+url)
				return None
			return res.status_code, url, path


if __name__ == '__main__':

	# Modifying the logger's level to ERROR to prevent console spam
	logging.getLogger("urllib3").setLevel(logging.ERROR)
	logging.getLogger("requests").setLevel(logging.ERROR)

	urllib3.disable_warnings()

	# Parsing the parameters.
	desc = '''\
               _     _
     ___ ___ _| |___| |_ _ _ ___ ___ ___
    |  _| . | . | -_| . | | |- _| -_|   |
    |___|___|___|___|___|_  |___|___|_|_|
         https://dsda.ru|___|
 	\n'''



	desc += '''Asynchronous tool to discovery aviablility of websites paths.\n'''
	desc += '''Locates resources in websites based on a list of paths.\n'''
	desc += '''Check out the "pathlist" directory for examples.\n'''

	parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('-u', dest='base_url', help='The target website to scan or path to file with domains list. (Scheme required!)', required=1)
	parser.add_argument('-l', dest='list_file', help='A file containing paths or directory with this files.',default=config.io.DEFAULT_PATHS_LIST_FILE)
	parser.add_argument('-w', dest='workers_count', help='Workers (threads) count. (default=10)',default=config.workers.WORKERS_COUNT)
	parser.add_argument('-d', dest='request_delay', help='Delay between requests. (default=0.03)',default=config.http.DELAY)
	parser.add_argument('-t', dest='timeout', help='Request timeout. (default=3)',default=config.http.TIMEOUT)
	parser.add_argument('-s', dest='subdomains_list', help='A file containing subdomains')
	parser.add_argument('-o', dest='output_file', help='A file to output',default=config.io.VALID_ENDPOINTS_FILE)
	parser.add_argument('-ua', dest='user_agent', help='Set user-agent manually',default=config.http.USER_AGENT)

	if len(sys.argv) <= 1:
		parser.print_usage(sys.stderr)
		sys.exit(1)

	options = parser.parse_args()
	list_file = options.list_file
	base_url = options.base_url
	output_file = options.output_file
	subdomains_list = options.subdomains_list
	config.http.USER_AGENT = options.user_agent
	config.workers.WORKERS_COUNT = options.user_agent
	config.http.DELAY = options.request_delay
	config.http.TIMEOUT = options.timeout

	if (os.path.isdir(base_url) or os.path.isfile(base_url)):
		FilesFactory(base_url)
		urls = FilesFactory.urls
	else:
		urls = [base_url]


	if subdomains_list is not None:
		sub_urls = []
		h = open(subdomains_list, 'r')
		subdomains_list = h.read().splitlines()
			
		for u in urls:
			uf = UrlFactory()
			sub_urls+=uf.make_subdomains(url=u, subdomains=subdomains_list)

		urls = sub_urls

	for u in urls:
		fuzzer = AsyncURLFuzzer(u, list_file, output_file=output_file)
		fuzzer.start()