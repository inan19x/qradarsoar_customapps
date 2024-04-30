import resilient
import time
import json
import re
import csv
import os
import smtplib
import ssl
import datetime as dt
import locale
import calendar

from calendar import monthrange
from datetime import datetime, timedelta

def main():

	yesterday   = dt.date.today() - timedelta(1)
	today	   = dt.date.today()
	# yesterday = dt.date(2019, 12, 30)
	# today = dt.date(2019, 12, 31)

	start_date  = int(time.mktime(yesterday.timetuple())*1000)
	end_date	= int(time.mktime(today.timetuple())*1000)

	list_incident = count_active_incident()
	
	info = {}
	info['date'] = dt.date.strftime(yesterday, '%Y%m%d')
	info['type'] = 'Daily'

def count_active_incident():

	TAG_RE = re.compile(r'<[^>]+>')
	parser = resilient.ArgumentParser(config_file=resilient.get_config_file())
	opts = parser.parse_args()

	client = resilient.get_client(opts)

	# prepare the future
	body = {
		"filters": [
			{
				"conditions": [
					{
						"field_name": "plan_status",
						"method": "equals",
						"value": "Active"
					}
				],
				"logic_type" : "any"
			}
		],
		'start': 0,
		'length': 1000,
		'sorts': [
			{
				'field_name': 'id',
				'type': 'asc'
			}
		]
	}

	uri = "/incidents/query_paged?return_level=normal"
	incidents = client.post(uri, body)
	incident_ids = []

	while incidents.get('data'):
		data = incidents.get('data')
		
		for result in data:
			incident_ids.append(result['id'])
			
		body['start'] = len(data) + body['start']

		incidents = client.post(uri, body)

	incident_ids.sort()

	uri = "/types"

	types = client.get(uri)

	severity_code = {}
	incident_type_ids = {}
	assigned_group = {}
	plan_status = {}

	list_incident = []

	for inc_id in incident_ids:
		list_incident_ahey = []

		uri = "/incidents/{}".format(inc_id)
		the_incident = client.get(uri)

		yes = datetime.strptime(datetime.fromtimestamp(int(the_incident['create_date'])/1000).strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')
		days = yes-datetime.now()
		days = -1*days.days

		uri = '/incidents/{}'.format(inc_id)

		incident = client.get(uri)

		# Update incident days alive record
		incident['properties']['days_alive'] = days
        
		client.put(uri, incident)

	return list_incident


if __name__ == "__main__":
	main()
