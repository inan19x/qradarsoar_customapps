# qradarsoar_customapps
These scripts are some sample apps created for resilient-circuits of IBM QRadar SOAR

hello_world.py - sample scripts how to log a "Hello world" text to resilient-circuits logger
escalation_email_processor.py - script that will be triggered when "Send Escalation Email" action menu item clicked, and will read a defined template from SOC_Playbook.xlsx file for sending an email.
incident_category_processor.py - script that will be triggered and read a defined template from SOC_Playbook.xlsx file for categorize an Incident
incident_days_alive_counter.py - script that will check time of now and compare with an incident date of creation for counting how many days the incident occured
SOC_Playbook.xlsx - a master file as reference for above scripts
