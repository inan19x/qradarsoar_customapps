import resilient
import re
import json 
import logging 
import smtplib
import ssl
import openpyxl
import os
import resilient_lib
import time
import shutil
import email
import email.header
import email.mime.multipart

from datetime import datetime
from xml.dom import minidom

from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from circuits.core.handlers import handler
from resilient_circuits.actions_component import ResilientComponent, ActionMessage

logger = logging.getLogger(__name__)

class EscalationEmailProcessor(ResilientComponent):
	# Subscribe to the Action Module message destination named 'hello_world'
	channel = 'actions.hello_world'

	# first escalation
	@handler('log_hello_world')
	def _log_hello_world_handler_function(self, event, headers, *args, **kwargs):
		logger.info("Hello World")