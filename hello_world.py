import resilient
import logging 
import resilient_lib

from circuits.core.handlers import handler
from resilient_circuits.actions_component import ResilientComponent, ActionMessage

logger = logging.getLogger(__name__)

class LogHelloWorld(ResilientComponent):
	# Subscribe to the Action Module message destination named 'hello_world'
	channel = 'actions.hello_world'

	# first escalation
	@handler('log_hello_world')
	def _log_hello_world_handler_function(self, event, headers, *args, **kwargs):
		logger.info("Hello World")
