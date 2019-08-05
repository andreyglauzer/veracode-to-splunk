#!/usr/bin/python3
# -*- coding: utf-8 -*-

__author__ = 'Andrey Glauzer'
__license__ = "MIT"
__version__ = "1.0.1"
__status__ = "Development"

import re
import os
import sys
import csv
import time
import json
import base64
import sqlite3
import argparse
import yaml
import logging
import datetime
import requests
import xmltodict
import importlib
import urllib.parse
import pprint
from datetime import date
from random import choice
from xml.parsers.expat import ExpatError


class DataBase:
	def __init__(self,
		database_path=None,
		database_name=None,
		):

		self.logger = logging.getLogger('Database')
		self.logger.info('Checking Database.')

		self.database_path = database_path
		self.database_name = database_name

		if not os.path.exists('{path}/{filename}'.format(path=self.database_path, filename=self.database_name)):
			conn = sqlite3.connect('{path}/{filename}'.format(path=self.database_path, filename=self.database_name))
			cursor = conn.cursor()

			cursor.execute('CREATE TABLE IF NOT EXISTS VERACODE ( id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,'
			'tag TEXT, uid TEXT);')

			conn.commit()
			conn.close()
		else:
			conn = sqlite3.connect('{path}/{filename}'.format(path=self.database_path, filename=self.database_name))
			cursor = conn.cursor()

			cursor.execute('CREATE TABLE IF NOT EXISTS VERACODE ( id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,'
			'tag TEXT, uid TEXT);')

			conn.commit()
			conn.close()


	def compare(self,
		tag=None,
		uid=None,):
		self.logger.debug('Comparing SCAN with what you already have in the database.')
		conn = sqlite3.connect('{path}/{filename}'.format(path=self.database_path, filename=self.database_name))
		cursor = conn.cursor()
		r = cursor.execute("SELECT * FROM VERACODE WHERE tag='{tag}' AND uid='{uid}';".format(tag=tag,
					uid=uid))


		return r.fetchall()

	def save(self,
		tag=None,
		uid=None,):
		self.logger.debug('Saving the SCAN in the database..')
		conn = sqlite3.connect('{path}/{filename}'.format(path=self.database_path, filename=self.database_name))
		cursor = conn.cursor()
		cursor.execute("""
		INSERT INTO VERACODE (tag,uid)
		VALUES ('%s', '%s')
		""" % (tag,uid))
		conn.commit()
		conn.close()

class XMLAPI:
	def __init__(self,
		database_path=None,
		database_name=None,
		save_log_dir=None,
		user=None,
		passwd=None,
		output_file=None,
		debug=None):

		if debug:
			logging.basicConfig(
					level=logging.INFO,
					format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
					datefmt='%Y-%m-%d %H:%M:%S',
			)
		else:
			logging.basicConfig(
					level=logging.DEBUG,
					format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
					datefmt='%Y-%m-%d %H:%M:%S',
			)

		self.logger = logging.getLogger('API Veracode XML')

		self.output_file = output_file
		self.database_path = database_path
		self.database_name = database_name
		self.splunk_dir = save_log_dir
		self.user = user
		self.passwd = passwd
		self.baseurl = "https://analysiscenter.veracode.com/api/5.0/"
		self.session = requests.session()

		self.database = DataBase(
			database_path=self.database_path,
			database_name=self.database_name,
		)

		self.desktop_agents = [
				'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:60.0) Gecko/20100101 Firefox/60.0'
		]

	@property
	def random_headers(self):
		auth = "Basic {}".format(self.stringToBase64(user=self.user,passwd=self.passwd).decode('UTF-8'))

		header =  {
			'User-Agent': choice(self.desktop_agents),
			'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
			'Authorization': auth
			}

		return header

	@property
	def start(self):
		for infos_apps in json.loads(self.getapplist())['applist']['app']:
			app_id = infos_apps['@app_id']
			app_name = infos_apps['@app_name']

			self.logger.info('Getting app builds {0}.'.format(app_name))
			apps_builds_list = self.getbuildlist(app_id=app_id)

			self.logger.debug('Exception to check apps that have build.')
			try:
				if int(len(json.loads(apps_builds_list)['buildlist']['build'])) == 3:
					self.logger.info('The app {name} has {number} build.'.format(
						name=app_name,
						number=1))
				else:
					self.logger.info('The app {name} has {number} builds.'.format(
						name=app_name,
						number=int(len(json.loads(apps_builds_list)['buildlist']['build']))))

				try:
					self.logger.debug(' Obtendo as builds.')
					for build_app in json.loads(apps_builds_list)['buildlist']['build']:
						build_id = build_app['@build_id']
						policy_updated_date_build = build_app['@policy_updated_date']

						self.logger.debug('Checking if the build is already in the database.')
						compare = self.database.compare(
							tag=app_name,
							uid=build_id,
						)

						if compare:
							self.logger.debug('Build {0} is already in the database.'.format(build_id))
						else:
							self.logger.info('Getting the Build {0}.'.format(build_id))
							self.logger.debug('Saving to the database.')

							self.database.save(
								tag=app_name,
								uid=build_id)

							if self.output_file.lower() == 'csv':
								self.clearreport(
									report=self.detailedreport(build=build_id))
							elif self.output_file.lower() == 'json':
								filename = '{0}/{1}-{2}.json'.format(
									self.splunk_dir,
									app_name.replace(' ','-'),
									build_id)
								if not os.path.exists(filename):
									arquivo = open(filename, 'w', encoding="utf-8")
									arquivo.close()

								arquivo = open(filename, 'r', encoding="utf-8")
								conteudo = arquivo.readlines()
								conteudo.append(self.detailedreport(build=build_id)+'\n')
								arquivo = open(filename, 'w', encoding="utf-8")
								arquivo.writelines(conteudo)
								arquivo.close()
							elif self.output_file.lower() == 'xml':
								filename = '{0}/{1}-{2}.xml'.format(
									self.splunk_dir,
									app_name.replace(' ','-'),
									build_id)
								if not os.path.exists(filename):
									arquivo = open(filename, 'w', encoding="utf-8")
									arquivo.close()

								arquivo = open(filename, 'r', encoding="utf-8")
								conteudo = arquivo.readlines()
								conteudo.append(self.detailedreport(build=build_id))
								arquivo = open(filename, 'w', encoding="utf-8")
								arquivo.writelines(conteudo)
								arquivo.close()


				except (TypeError) as e:
					build_id = json.loads(apps_builds_list)['buildlist']['build']['@build_id']
					policy_updated_date_build = json.loads(apps_builds_list)['buildlist']['build']['@policy_updated_date']

					compare = self.database.compare(
						tag=app_name,
						uid=build_id,
					)

					if compare:
						self.logger.debug('Build {0} is already in the database.'.format(build_id))
					else:
						self.logger.info('Getting the Build {0}.'.format(build_id))
						self.logger.debug('Saving to the database.')

						self.database.save(
							tag=app_name,
							uid=build_id)

						if self.output_file.lower() == 'csv':
							self.clearreport(
								report=self.detailedreport(build=build_id))
						elif self.output_file.lower() == 'json':
							filename = '{0}/{1}-{2}.json'.format(
								self.splunk_dir,
								app_name.replace(' ','-'),
								build_id)
							if not os.path.exists(filename):
								arquivo = open(filename, 'w', encoding="utf-8")
								arquivo.close()

							arquivo = open(filename, 'r', encoding="utf-8")
							conteudo = arquivo.readlines()
							conteudo.append(self.detailedreport(build=build_id)+'\n')
							arquivo = open(filename, 'w', encoding="utf-8")
							arquivo.writelines(conteudo)
							arquivo.close()
						elif self.output_file.lower() == 'xml':
							filename = '{0}/{1}-{2}.xml'.format(
								self.splunk_dir,
								app_name.replace(' ','-'),
								build_id)
							if not os.path.exists(filename):
								arquivo = open(filename, 'w', encoding="utf-8")
								arquivo.close()

							arquivo = open(filename, 'r', encoding="utf-8")
							conteudo = arquivo.readlines()
							conteudo.append(self.detailedreport(build=build_id))
							arquivo = open(filename, 'w', encoding="utf-8")
							arquivo.writelines(conteudo)
							arquivo.close()



			except (KeyError) as e:
				if 'build' in str(e):
					self.logger.error('The app {} has no build.'.format(app_name))
					pass

	def repname(self, name=None):
		self.logger.debug('Getting additional information for Splunk filters.')
		self.logger.debug('Information passed by the customer.')
		if name is not None:
			try:
				rex = re.compile("(\w+)-(\w+)-(\w+)-(.*[A-za-z]\w+)")
				full_rex = rex.match(name)
				tecnologia = full_rex.group(1)
				sigla = full_rex.group(2)
				modulo = full_rex.group(3)
				componente = full_rex.group(4)

				return tecnologia, sigla, modulo, componente
			except (AttributeError) as e:
				self.logger.debug('The name is non-standard, it will be saved as Null.')
				return False

	def stringToBase64(self,user=None, passwd=None):
		if user is not None:
			self.logger.debug('Converting username and password to Base64.')
			userpass = "{0}:{1}".format(user, passwd)
			return base64.b64encode(userpass.encode('utf-8'))


	def getapplist(self):
		self.logger.info('Getting Apps Available on Veracode.')
		request = self.session.post(self.baseurl+"getapplist.do", headers=self.random_headers)
		appslist = xmltodict.parse(request.content)

		return json.dumps(appslist)

	def getbuildlist(self, app_id=None):
		if app_id is not None:
			request = self.session.post(
				self.baseurl+'getbuildlist.do',
				headers=self.random_headers,
				data={'app_id': app_id})

			if request.status_code == 200:
				buildstoapp = xmltodict.parse(request.content)
				return json.dumps(buildstoapp)
			else:
				self.logger.error('Unable to get APP Builds {}. \ Please check manually using Curl, or make sure veracode API service is not down.'.format(app_id))
				exit(0)

	def detailedreport(self, build=None):
		if build is not None:
			if self.output_file.lower() == 'xml':
				request = self.session.post(
					self.baseurl+'detailedreport.do?build_id={}'.format(build),
					headers=self.random_headers,)
				return request.text
			else:
				request = self.session.post(
					self.baseurl+'detailedreport.do?build_id={}'.format(build),
					headers=self.random_headers,)
				detailreport = xmltodict.parse(request.content)
				return json.dumps(detailreport)


	def output(
		self,
		app_report_format_version=None,
		app_account_id=None,
		app_app_name=None,
		app_app_id=None,
		app_analysis_id=None,
		app_static_analysis_unit_id=None,
		app_sandbox_id=None,
		app_first_build_submitted_date=None,
		app_version=None,
		app_build_id=None,
		app_submitter=None,
		app_platform=None,
		app_assurance_level=None,
		app_business_criticality=None,
		app_generation_date=None,
		app_veracode_level=None,
		app_total_flaws=None,
		app_flaws_not_mitigated=None,
		app_teams=None,
		app_life_cycle_stage=None,
		app_planned_deployment_date=None,
		app_last_update_time=None,
		app_is_latest_build=None,
		app_policy_name=None,
		app_policy_version=None,
		app_policy_compliance_status=None,
		app_policy_rules_status=None,
		app_grace_period_expired=None,
		app_scan_overdue=None,
		app_business_owner=None,
		app_business_unit=None,
		app_tags=None,
		app_legacy_scan_engine=None,
		analysis_rating=None,
		analysis_score=None,
		analysis_submitted_date=None,
		analysis_published_date=None,
		analysis_version=None,
		analysis_next_scan_due=None,
		analysis_analysis_size_bytes=None,
		analysis_engine_version=None,
		status_new=None,
		status_reopen=None,
		status_open=None,
		status_cannot_reproduce=None,
		status_fixed=None,
		status_total=None,
		status_not_mitigated=None,
		status_sev_1_change=None,
		status_sev_2_change=None,
		status_sev_3_change=None,
		status_sev_4_change=None,
		status_sev_5_change=None,
		pcirelated=None,
		desc_list=None,
		rem_list=None,
		cwename=None,
		owasp=None,
		owasp2013=None,
		sans=None,
		owaspmobile=None,
		severity=None,
		categoryname=None,
		count=None,
		issueid=None,
		module=None,
		type=None,
		description=None,
		note=None,
		cweid=None,
		remediationeffort=None,
		exploitLevel=None,
		categoryid=None,
		date_first_occurrence=None,
		remediation_status=None,
		cia_impact=None,
		grace_period_expires=None,
		affects_policy_compliance=None,
		mitigation_status=None,
		mitigation_status_desc=None,
		sourcefile=None,
		line=None,
		sourcefilepath=None,
		scope=None,
		functionprototype=None,
		functionrelativelocation=None,):

		self.logger.debug('Starting the process to save the file as CSV.')
		get_real_names = self.repname(name=app_app_name.replace(' ','-'))

		if get_real_names:
			tecnologia = get_real_names[0]
			sigla = get_real_names[1]
			modulo = get_real_names[2]
			componente = get_real_names[3]
		else:
			tecnologia = "Null"
			sigla = "Null"
			modulo = "Null"
			componente = app_app_name.replace(' ','-')

		if not os.path.exists(self.splunk_dir):
			os.mkdir(self.splunk_dir)
			self.logger.debug('It was necessary to create folder.')

		name_file = '{dir}/{name}_{build}_{date}.csv'.format(
			dir=self.splunk_dir,
			name=app_app_name.replace(' ','-'),
			build=app_build_id,
			date=datetime.datetime.now().strftime("%Y_%m_%d")
		)

		if not os.path.exists(name_file):
			arquivo = open(name_file, 'w', encoding="utf8")
			arquivo.close()
			with open(name_file, 'w') as csvfile:
				filewriter = csv.writer(csvfile, delimiter=',')
				filewriter.writerow([
					'tecnologia',
					'sigla',
					'modulo',
					'componente',
					'app_report_format_version',
					'app_account_id',
					'app_app_name',
					'app_app_id',
					'app_analysis_id',
					'app_static_analysis_unit_id',
					'app_sandbox_id',
					'app_first_build_submitted_date',
					'app_version',
					'app_build_id',
					'app_submitter',
					'app_platform',
					'app_assurance_level',
					'app_business_criticality',
					'app_generation_date',
					'app_veracode_level',
					'app_total_flaws',
					'app_flaws_not_mitigated',
					'app_teams',
					'app_life_cycle_stage',
					'app_planned_deployment_date',
					'app_last_update_time',
					'app_is_latest_build',
					'app_policy_name',
					'app_policy_version',
					'app_policy_compliance_status',
					'app_policy_rules_status',
					'app_grace_period_expired',
					'app_scan_overdue',
					'app_business_owner',
					'app_business_unit',
					'app_tags',
					'app_legacy_scan_engine',
					'analysis_rating',
					'analysis_score',
					'analysis_submitted_date',
					'analysis_published_date',
					'analysis_version',
					'analysis_next_scan_due',
					'analysis_analysis_size_bytes',
					'analysis_engine_version',
					'status_new',
					'status_reopen',
					'status_open',
					'status_cannot_reproduce',
					'status_fixed',
					'status_total',
					'status_not_mitigated',
					'status_sev_1_change',
					'status_sev_2_change',
					'status_sev_3_change',
					'status_sev_4_change',
					'status_sev_5_change',
					'desc_list',
					'rem_list',
					'cwename',
					'owasp',
					'owasp2013',
					'sans',
					'owaspmobile',
					'severity',
					'categoryname',
					'count',
					'issueid',
					'module',
					'type',
					'description',
					'note',
					'cweid',
					'remediationeffort',
					'exploitLevel',
					'categoryid',
					'pcirelated',
					'date_first_occurrence',
					'remediation_status',
					'cia_impact',
					'grace_period_expires',
					'affects_policy_compliance',
					'mitigation_status',
					'mitigation_status_desc',
					'sourcefile',
					'line',
					'sourcefilepath',
					'scope',
					'functionprototype',
					'functionrelativelocation',
				])
		with open(name_file, 'a') as csvfile:
			filewriter = csv.writer(csvfile, delimiter=',')
			filewriter.writerow([
				tecnologia,
				sigla,
				modulo,
				componente,
				app_report_format_version,
				app_account_id,
				app_app_name,
				app_app_id,
				app_analysis_id,
				app_static_analysis_unit_id,
				app_sandbox_id,
				app_first_build_submitted_date,
				app_version,
				app_build_id,
				app_submitter,
				app_platform,
				app_assurance_level,
				app_business_criticality,
				app_generation_date,
				app_veracode_level,
				app_total_flaws,
				app_flaws_not_mitigated,
				app_teams,
				app_life_cycle_stage,
				app_planned_deployment_date,
				app_last_update_time,
				app_is_latest_build,
				app_policy_name,
				app_policy_version,
				app_policy_compliance_status,
				app_policy_rules_status,
				app_grace_period_expired,
				app_scan_overdue,
				app_business_owner,
				app_business_unit,
				app_tags,
				app_legacy_scan_engine,
				analysis_rating,
				analysis_score,
				analysis_submitted_date,
				analysis_published_date,
				analysis_version,
				analysis_next_scan_due,
				analysis_analysis_size_bytes,
				analysis_engine_version,
				status_new,
				status_reopen,
				status_open,
				status_cannot_reproduce,
				status_fixed,
				status_total,
				status_not_mitigated,
				status_sev_1_change,
				status_sev_2_change,
				status_sev_3_change,
				status_sev_4_change,
				status_sev_5_change,
				' // '.join(str(x) for x in desc_list).replace('"','') \
				.replace("'", "") \
				.replace('\n', '') \
				.replace('\s', '') \
				.replace('\r', '') \
				.replace('\t', '') \
				.replace(r'\n', '') \
				.replace(r'\s', '') \
				.replace(r'\r', '') \
				.replace(r'\t', '') \
				.replace(',', '') \
				.replace(';', '') \
				.replace('‘', '') \
				.replace('’', '') \
				.replace('}', '') \
				.replace('{', '') \
				.replace('&', ''),
				' // '.join(str(x) for x in rem_list).replace('"','') \
				.replace("'", "") \
				.replace('\n', '') \
				.replace('\s', '') \
				.replace('\r', '') \
				.replace('\t', '') \
				.replace(r'\n', '') \
				.replace(r'\s', '') \
				.replace(r'\r', '') \
				.replace(r'\t', '') \
				.replace(',', '') \
				.replace(';', '') \
				.replace('‘', '') \
				.replace('’', '') \
				.replace('}', '') \
				.replace('{', '') \
				.replace('&', ''),
				cwename,
				owasp \
				.replace('1027', 'Injection') \
				.replace('1028', 'Broken Authentication') \
				.replace('1029', 'Sensitive Data Exposure') \
				.replace('1030', 'XML External Entities (XXE)') \
				.replace('1031', 'Broken Access Control') \
				.replace('1032', 'Security Misconfiguration') \
				.replace('1033', 'Cross-Site Scripting (XSS)') \
				.replace('1034', 'Insecure Deserialization') \
				.replace('1036', 'Insufficient Logging & Monitoring'),
				owasp2013,
				sans,
				owaspmobile,
				severity,
				categoryname,
				count,
				issueid,
				module,
				type,
				description.replace('"','') \
				.replace("'", "") \
				.replace('\n', '') \
				.replace('\s', '') \
				.replace('\r', '') \
				.replace('\t', '') \
				.replace(r'\n', '') \
				.replace(r'\s', '') \
				.replace(r'\r', '') \
				.replace(r'\t', '') \
				.replace(',', '') \
				.replace(';', '') \
				.replace('‘', '') \
				.replace('’', '') \
				.replace('}', '') \
				.replace('{', '') \
				.replace('&', ''),
				note,
				cweid,
				remediationeffort,
				exploitLevel,
				categoryid,
				pcirelated,
				date_first_occurrence,
				remediation_status,
				cia_impact,
				grace_period_expires,
				affects_policy_compliance,
				mitigation_status \
				.replace("none", "Null"),
				mitigation_status_desc,
				sourcefile,
				line,
				sourcefilepath,
				scope,
				functionprototype,
				functionrelativelocation,
			])

	def clearreport(self, report=None):
		if report is not None:
			self.logger.debug('Clearing the variables.')
			app_report_format_version = None
			app_account_id = None
			app_app_name = None
			app_app_id = None
			app_analysis_id = None
			app_static_analysis_unit_id = None
			app_sandbox_id = None
			app_first_build_submitted_date = None
			app_version = None
			app_build_id = None
			app_submitter = None
			app_platform = None
			app_assurance_level = None
			app_business_criticality = None
			app_generation_date = None
			app_veracode_level = None
			app_total_flaws = None
			app_flaws_not_mitigated = None
			app_teams = None
			app_life_cycle_stage = None
			app_planned_deployment_date = None
			app_last_update_time = None
			app_is_latest_build = None
			app_policy_name = None
			app_policy_version = None
			app_policy_compliance_status = None
			app_policy_rules_status = None
			app_grace_period_expired = None
			app_scan_overdue = None
			app_business_owner = None
			app_business_unit = None
			app_tags = None
			app_legacy_scan_engine = None
			analysis_rating = None
			analysis_score = None
			analysis_submitted_date = None
			analysis_published_date = None
			analysis_version = None
			analysis_next_scan_due = None
			analysis_analysis_size_bytes = None
			analysis_engine_version = None
			status_new = None
			status_reopen = None
			status_open = None
			status_cannot_reproduce = None
			status_fixed = None
			status_total = None
			status_not_mitigated = None
			status_sev_1_change = None
			status_sev_2_change = None
			status_sev_3_change = None
			status_sev_4_change = None
			status_sev_5_change = None
			categoryid = None
			categoryname = None
			pcirelated = None
			desc_list = None
			rem_list = None
			cweid = None
			cwename = None
			pcirelated = None
			owasp = None
			owasp2013 = None
			sans = None
			owaspmobile = None
			severity = None
			categoryname = None
			count = None
			issueid = None
			module = None
			type = None
			description = None
			note = None
			cweid = None
			remediationeffort = None
			exploitLevel = None
			categoryid = None
			pcirelated = None
			date_first_occurrence = None
			remediation_status = None
			cia_impact = None
			grace_period_expires = None
			affects_policy_compliance = None
			mitigation_status = None
			mitigation_status_desc = None
			sourcefile = None
			line = None
			sourcefilepath = None
			scope = None
			functionprototype = None
			functionrelativelocation = None

			self.logger.debug('Dump the json report.')
			datajson = json.loads(report)

			app_report_format_version = datajson['detailedreport']['@report_format_version']
			app_account_id = datajson['detailedreport']['@account_id']
			app_app_name = datajson['detailedreport']['@app_name']
			app_app_id = datajson['detailedreport']['@app_id']
			app_analysis_id = datajson['detailedreport']['@analysis_id']
			app_static_analysis_unit_id = datajson['detailedreport']['@static_analysis_unit_id']
			app_sandbox_id = datajson['detailedreport']['@sandbox_id']
			app_first_build_submitted_date = datajson['detailedreport']['@first_build_submitted_date']
			app_version = datajson['detailedreport']['@version']
			app_build_id = datajson['detailedreport']['@build_id']
			app_submitter = datajson['detailedreport']['@submitter']
			app_platform = datajson['detailedreport']['@platform']
			app_assurance_level = datajson['detailedreport']['@assurance_level']
			app_business_criticality = datajson['detailedreport']['@business_criticality']
			app_generation_date = datajson['detailedreport']['@generation_date']
			app_veracode_level = datajson['detailedreport']['@veracode_level']
			app_total_flaws = datajson['detailedreport']['@total_flaws']
			app_flaws_not_mitigated = datajson['detailedreport']['@flaws_not_mitigated']
			app_teams = datajson['detailedreport']['@teams']
			app_life_cycle_stage = datajson['detailedreport']['@life_cycle_stage']
			app_planned_deployment_date = datajson['detailedreport']['@planned_deployment_date']
			app_last_update_time = datajson['detailedreport']['@last_update_time']
			app_is_latest_build = datajson['detailedreport']['@is_latest_build']
			app_policy_name = datajson['detailedreport']['@policy_name']
			app_policy_version = datajson['detailedreport']['@policy_version']
			app_policy_compliance_status = datajson['detailedreport']['@policy_compliance_status']
			app_policy_rules_status = datajson['detailedreport']['@policy_rules_status']
			app_grace_period_expired = datajson['detailedreport']['@grace_period_expired']
			app_scan_overdue = datajson['detailedreport']['@scan_overdue']
			app_business_owner = datajson['detailedreport']['@business_owner']
			app_business_unit = datajson['detailedreport']['@business_unit']
			app_tags = datajson['detailedreport']['@tags']
			app_legacy_scan_engine = datajson['detailedreport']['@legacy_scan_engine']

			self.logger.debug('# static_analysis')
			analysis_rating = datajson['detailedreport']['static-analysis']['@rating']
			analysis_score = datajson['detailedreport']['static-analysis']['@score']
			analysis_submitted_date = datajson['detailedreport']['static-analysis']['@submitted_date']
			analysis_published_date = datajson['detailedreport']['static-analysis']['@published_date']
			analysis_version = datajson['detailedreport']['static-analysis']['@version']
			analysis_next_scan_due = datajson['detailedreport']['static-analysis']['@next_scan_due']
			analysis_analysis_size_bytes = datajson['detailedreport']['static-analysis']['@analysis_size_bytes']
			analysis_engine_version = datajson['detailedreport']['static-analysis']['@engine_version']


			self.logger.debug('# Obtendo informações de flaw status.')
			status_new = datajson['detailedreport']['flaw-status']['@new']
			status_reopen = datajson['detailedreport']['flaw-status']['@reopen']
			status_open = datajson['detailedreport']['flaw-status']['@open']
			status_cannot_reproduce = datajson['detailedreport']['flaw-status']['@cannot-reproduce']
			status_fixed = datajson['detailedreport']['flaw-status']['@fixed']
			status_total = datajson['detailedreport']['flaw-status']['@total']
			status_not_mitigated = datajson['detailedreport']['flaw-status']['@not_mitigated']
			status_sev_1_change = datajson['detailedreport']['flaw-status']['@sev-1-change']
			status_sev_2_change = datajson['detailedreport']['flaw-status']['@sev-2-change']
			status_sev_3_change = datajson['detailedreport']['flaw-status']['@sev-3-change']
			status_sev_4_change = datajson['detailedreport']['flaw-status']['@sev-4-change']
			status_sev_5_change = datajson['detailedreport']['flaw-status']['@sev-5-change']


			for vulns in datajson['detailedreport']['severity']:
				if len(vulns) > 1:
					if len(vulns['category']) == 6:
						self.logger.debug('6: The value of categories is == to 6 this makes a respectful deal.')
						try:
							for categories in vulns['category']:

								desc_list = []
								try:
									for desc in categories['desc']['para']:
										desc_list.append(desc['@text'])
								except (TypeError) as e:
									self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
									desc_list.append(categories['desc']['para']['@text'])

								rem_list = []
								try:
									for recommendations in categories['recommendations']['para']:
										rem_list.append(recommendations['@text'])
								except (TypeError) as e:
									self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
									rem_list.append(categories['recommendations']['para']['@text'])

								try:
									for cwe in categories['cwe']:
										cweid = cwe['@cweid']
										cwename = cwe['@cwename']
										pcirelated = cwe['@pcirelated']

										try:
											owasp = cwe['@owasp']
										except (KeyError) as e:
											self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
											owasp = "Null"
										try:
											owasp2013 = cwe['@owasp2013']
										except (KeyError) as e:
											self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
											owasp2013 = "Null"
										try:
											sans = cwe['@sans']
										except (KeyError) as e:
											self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
											sans = "Null"
										try:
											owaspmobile = cwe['@owaspmobile']
										except (KeyError) as e:
											self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
											owaspmobile = "Null"

										description = cwe['description']['text']['@text']

										try:
											for staticflaws in cwe['staticflaws']['flaw']:
												severity = staticflaws['@severity']
												categoryname = staticflaws['@categoryname']
												count = staticflaws['@count']
												issueid = staticflaws['@issueid']
												module = staticflaws['@module']
												type = staticflaws['@type']
												description = staticflaws['@description']
												note = staticflaws['@note']
												cweid = staticflaws['@cweid']
												remediationeffort = staticflaws['@remediationeffort']
												exploitLevel = staticflaws['@exploitLevel']
												categoryid = staticflaws['@categoryid']
												pcirelated = staticflaws['@pcirelated']
												date_first_occurrence = staticflaws['@date_first_occurrence']
												remediation_status = staticflaws['@remediation_status']
												cia_impact = staticflaws['@cia_impact']
												grace_period_expires = staticflaws['@grace_period_expires']
												affects_policy_compliance = staticflaws['@affects_policy_compliance']
												mitigation_status = staticflaws['@mitigation_status']
												mitigation_status_desc = staticflaws['@mitigation_status_desc']
												sourcefile = staticflaws['@sourcefile']
												line = staticflaws['@line']
												sourcefilepath = staticflaws['@sourcefilepath']
												scope = staticflaws['@scope']
												functionprototype = staticflaws['@functionprototype']
												functionrelativelocation = staticflaws['@functionrelativelocation']

												self.output(
													app_report_format_version=app_report_format_version,
													app_account_id=app_account_id,
													app_app_name=app_app_name,
													app_app_id=app_app_id,
													app_analysis_id=app_analysis_id,
													app_static_analysis_unit_id=app_static_analysis_unit_id,
													app_sandbox_id=app_sandbox_id,
													app_first_build_submitted_date=app_first_build_submitted_date,
													app_version=app_version,
													app_build_id=app_build_id,
													app_submitter=app_submitter,
													app_platform=app_platform,
													app_assurance_level=app_assurance_level,
													app_business_criticality=app_business_criticality,
													app_generation_date=app_generation_date,
													app_veracode_level=app_veracode_level,
													app_total_flaws=app_total_flaws,
													app_flaws_not_mitigated=app_flaws_not_mitigated,
													app_teams=app_teams,
													app_life_cycle_stage=app_life_cycle_stage,
													app_planned_deployment_date=app_planned_deployment_date,
													app_last_update_time=app_last_update_time,
													app_is_latest_build=app_is_latest_build,
													app_policy_name=app_policy_name,
													app_policy_version=app_policy_version,
													app_policy_compliance_status=app_policy_compliance_status,
													app_policy_rules_status=app_policy_rules_status,
													app_grace_period_expired=app_grace_period_expired,
													app_scan_overdue=app_scan_overdue,
													app_business_owner=app_business_owner,
													app_business_unit=app_business_unit,
													app_tags=app_tags,
													app_legacy_scan_engine=app_legacy_scan_engine,
													analysis_rating=analysis_rating,
													analysis_score=analysis_score,
													analysis_submitted_date=analysis_submitted_date,
													analysis_published_date=analysis_published_date,
													analysis_version=analysis_version,
													analysis_next_scan_due=analysis_next_scan_due,
													analysis_analysis_size_bytes=analysis_analysis_size_bytes,
													analysis_engine_version=analysis_engine_version,
													status_new=status_new,
													status_reopen=status_reopen,
													status_open=status_open,
													status_cannot_reproduce=status_cannot_reproduce,
													status_fixed=status_fixed,
													status_total=status_total,
													status_not_mitigated=status_not_mitigated,
													status_sev_1_change=status_sev_1_change,
													status_sev_2_change=status_sev_2_change,
													status_sev_3_change=status_sev_3_change,
													status_sev_4_change=status_sev_4_change,
													status_sev_5_change=status_sev_5_change,
													desc_list=desc_list,
													rem_list=rem_list,
													cwename=cwename,
													owasp=owasp,
													owasp2013=owasp2013,
													sans=sans,
													owaspmobile=owaspmobile,
													severity=severity,
													categoryname=categoryname,
													count=count,
													issueid=issueid,
													module=module,
													type=type,
													description=description,
													note=note,
													cweid=cweid,
													remediationeffort=remediationeffort,
													exploitLevel=exploitLevel,
													categoryid=categoryid,
													pcirelated=pcirelated,
													date_first_occurrence=date_first_occurrence,
													remediation_status=remediation_status,
													cia_impact=cia_impact,
													grace_period_expires=grace_period_expires,
													affects_policy_compliance=affects_policy_compliance,
													mitigation_status=mitigation_status,
													mitigation_status_desc=mitigation_status_desc,
													sourcefile=sourcefile,
													line=line,
													sourcefilepath=sourcefilepath,
													scope=scope,
													functionprototype=functionprototype,
													functionrelativelocation=functionrelativelocation)

										except (TypeError) as e:
											self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
											severity = cwe['staticflaws']['flaw']['@severity']
											categoryname = cwe['staticflaws']['flaw']['@categoryname']
											count = cwe['staticflaws']['flaw']['@count']
											issueid = cwe['staticflaws']['flaw']['@issueid']
											module = cwe['staticflaws']['flaw']['@module']
											type = cwe['staticflaws']['flaw']['@type']
											description = cwe['staticflaws']['flaw']['@description']
											note = cwe['staticflaws']['flaw']['@note']
											cweid = cwe['staticflaws']['flaw']['@cweid']
											remediationeffort = cwe['staticflaws']['flaw']['@remediationeffort']
											exploitLevel = cwe['staticflaws']['flaw']['@exploitLevel']
											categoryid = cwe['staticflaws']['flaw']['@categoryid']
											pcirelated = cwe['staticflaws']['flaw']['@pcirelated']
											date_first_occurrence = cwe['staticflaws']['flaw']['@date_first_occurrence']
											remediation_status = cwe['staticflaws']['flaw']['@remediation_status']
											cia_impact = cwe['staticflaws']['flaw']['@cia_impact']
											grace_period_expires = cwe['staticflaws']['flaw']['@grace_period_expires']
											affects_policy_compliance = cwe['staticflaws']['flaw']['@affects_policy_compliance']
											mitigation_status = cwe['staticflaws']['flaw']['@mitigation_status']
											mitigation_status_desc = cwe['staticflaws']['flaw']['@mitigation_status_desc']
											sourcefile = cwe['staticflaws']['flaw']['@sourcefile']
											line = cwe['staticflaws']['flaw']['@line']
											sourcefilepath = cwe['staticflaws']['flaw']['@sourcefilepath']
											scope = cwe['staticflaws']['flaw']['@scope']
											functionprototype = cwe['staticflaws']['flaw']['@functionprototype']
											functionrelativelocation = cwe['staticflaws']['flaw']['@functionrelativelocation']

											self.output(
												app_report_format_version=app_report_format_version,
												app_account_id=app_account_id,
												app_app_name=app_app_name,
												app_app_id=app_app_id,
												app_analysis_id=app_analysis_id,
												app_static_analysis_unit_id=app_static_analysis_unit_id,
												app_sandbox_id=app_sandbox_id,
												app_first_build_submitted_date=app_first_build_submitted_date,
												app_version=app_version,
												app_build_id=app_build_id,
												app_submitter=app_submitter,
												app_platform=app_platform,
												app_assurance_level=app_assurance_level,
												app_business_criticality=app_business_criticality,
												app_generation_date=app_generation_date,
												app_veracode_level=app_veracode_level,
												app_total_flaws=app_total_flaws,
												app_flaws_not_mitigated=app_flaws_not_mitigated,
												app_teams=app_teams,
												app_life_cycle_stage=app_life_cycle_stage,
												app_planned_deployment_date=app_planned_deployment_date,
												app_last_update_time=app_last_update_time,
												app_is_latest_build=app_is_latest_build,
												app_policy_name=app_policy_name,
												app_policy_version=app_policy_version,
												app_policy_compliance_status=app_policy_compliance_status,
												app_policy_rules_status=app_policy_rules_status,
												app_grace_period_expired=app_grace_period_expired,
												app_scan_overdue=app_scan_overdue,
												app_business_owner=app_business_owner,
												app_business_unit=app_business_unit,
												app_tags=app_tags,
												app_legacy_scan_engine=app_legacy_scan_engine,
												analysis_rating=analysis_rating,
												analysis_score=analysis_score,
												analysis_submitted_date=analysis_submitted_date,
												analysis_published_date=analysis_published_date,
												analysis_version=analysis_version,
												analysis_next_scan_due=analysis_next_scan_due,
												analysis_analysis_size_bytes=analysis_analysis_size_bytes,
												analysis_engine_version=analysis_engine_version,
												status_new=status_new,
												status_reopen=status_reopen,
												status_open=status_open,
												status_cannot_reproduce=status_cannot_reproduce,
												status_fixed=status_fixed,
												status_total=status_total,
												status_not_mitigated=status_not_mitigated,
												status_sev_1_change=status_sev_1_change,
												status_sev_2_change=status_sev_2_change,
												status_sev_3_change=status_sev_3_change,
												status_sev_4_change=status_sev_4_change,
												status_sev_5_change=status_sev_5_change,
												desc_list=desc_list,
												rem_list=rem_list,
												cwename=cwename,
												owasp=owasp,
												owasp2013=owasp2013,
												sans=sans,
												owaspmobile=owaspmobile,
												severity=severity,
												categoryname=categoryname,
												count=count,
												issueid=issueid,
												module=module,
												type=type,
												description=description,
												note=note,
												cweid=cweid,
												remediationeffort=remediationeffort,
												exploitLevel=exploitLevel,
												categoryid=categoryid,
												pcirelated=pcirelated,
												date_first_occurrence=date_first_occurrence,
												remediation_status=remediation_status,
												cia_impact=cia_impact,
												grace_period_expires=grace_period_expires,
												affects_policy_compliance=affects_policy_compliance,
												mitigation_status=mitigation_status,
												mitigation_status_desc=mitigation_status_desc,
												sourcefile=sourcefile,
												line=line,
												sourcefilepath=sourcefilepath,
												scope=scope,
												functionprototype=functionprototype,
												functionrelativelocation=functionrelativelocation)

								except (TypeError) as e:
									self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
									cweid = categories['cwe']['@cweid']
									cwename = categories['cwe']['@cwename']
									pcirelated = categories['cwe']['@pcirelated']
									try:
										owasp = categories['cwe']['@owasp']
									except (KeyError) as e:
										self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
										owasp = "Null"
									try:
										owasp2013 = categories['cwe']['@owasp2013']
									except (KeyError) as e:
										self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
										owasp2013 = "Null"
									try:
										sans = categories['cwe']['@sans']
									except (KeyError) as e:
										self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
										sans = "Null"
									try:
										owaspmobile = categories['cwe']['@owaspmobile']
									except (KeyError) as e:
										self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
										owaspmobile = "Null"

									try:
										for staticflaws in categories['cwe']['staticflaws']['flaw']:
											severity = staticflaws['@severity']
											categoryname = staticflaws['@categoryname']
											count = staticflaws['@count']
											issueid = staticflaws['@issueid']
											module = staticflaws['@module']
											type = staticflaws['@type']
											description = staticflaws['@description']
											note = staticflaws['@note']
											cweid = staticflaws['@cweid']
											remediationeffort = staticflaws['@remediationeffort']
											exploitLevel = staticflaws['@exploitLevel']
											categoryid = staticflaws['@categoryid']
											pcirelated = staticflaws['@pcirelated']
											date_first_occurrence = staticflaws['@date_first_occurrence']
											remediation_status = staticflaws['@remediation_status']
											cia_impact = staticflaws['@cia_impact']
											grace_period_expires = staticflaws['@grace_period_expires']
											affects_policy_compliance = staticflaws['@affects_policy_compliance']
											mitigation_status = staticflaws['@mitigation_status']
											mitigation_status_desc = staticflaws['@mitigation_status_desc']
											sourcefile = staticflaws['@sourcefile']
											line = staticflaws['@line']
											sourcefilepath = staticflaws['@sourcefilepath']
											scope = staticflaws['@scope']
											functionprototype = staticflaws['@functionprototype']
											functionrelativelocation = staticflaws['@functionrelativelocation']

											self.output(
												app_report_format_version=app_report_format_version,
												app_account_id=app_account_id,
												app_app_name=app_app_name,
												app_app_id=app_app_id,
												app_analysis_id=app_analysis_id,
												app_static_analysis_unit_id=app_static_analysis_unit_id,
												app_sandbox_id=app_sandbox_id,
												app_first_build_submitted_date=app_first_build_submitted_date,
												app_version=app_version,
												app_build_id=app_build_id,
												app_submitter=app_submitter,
												app_platform=app_platform,
												app_assurance_level=app_assurance_level,
												app_business_criticality=app_business_criticality,
												app_generation_date=app_generation_date,
												app_veracode_level=app_veracode_level,
												app_total_flaws=app_total_flaws,
												app_flaws_not_mitigated=app_flaws_not_mitigated,
												app_teams=app_teams,
												app_life_cycle_stage=app_life_cycle_stage,
												app_planned_deployment_date=app_planned_deployment_date,
												app_last_update_time=app_last_update_time,
												app_is_latest_build=app_is_latest_build,
												app_policy_name=app_policy_name,
												app_policy_version=app_policy_version,
												app_policy_compliance_status=app_policy_compliance_status,
												app_policy_rules_status=app_policy_rules_status,
												app_grace_period_expired=app_grace_period_expired,
												app_scan_overdue=app_scan_overdue,
												app_business_owner=app_business_owner,
												app_business_unit=app_business_unit,
												app_tags=app_tags,
												app_legacy_scan_engine=app_legacy_scan_engine,
												analysis_rating=analysis_rating,
												analysis_score=analysis_score,
												analysis_submitted_date=analysis_submitted_date,
												analysis_published_date=analysis_published_date,
												analysis_version=analysis_version,
												analysis_next_scan_due=analysis_next_scan_due,
												analysis_analysis_size_bytes=analysis_analysis_size_bytes,
												analysis_engine_version=analysis_engine_version,
												status_new=status_new,
												status_reopen=status_reopen,
												status_open=status_open,
												status_cannot_reproduce=status_cannot_reproduce,
												status_fixed=status_fixed,
												status_total=status_total,
												status_not_mitigated=status_not_mitigated,
												status_sev_1_change=status_sev_1_change,
												status_sev_2_change=status_sev_2_change,
												status_sev_3_change=status_sev_3_change,
												status_sev_4_change=status_sev_4_change,
												status_sev_5_change=status_sev_5_change,
												desc_list=desc_list,
												rem_list=rem_list,
												cwename=cwename,
												owasp=owasp,
												owasp2013=owasp2013,
												sans=sans,
												owaspmobile=owaspmobile,
												severity=severity,
												categoryname=categoryname,
												count=count,
												issueid=issueid,
												module=module,
												type=type,
												description=description,
												note=note,
												cweid=cweid,
												remediationeffort=remediationeffort,
												exploitLevel=exploitLevel,
												categoryid=categoryid,
												pcirelated=pcirelated,
												date_first_occurrence=date_first_occurrence,
												remediation_status=remediation_status,
												cia_impact=cia_impact,
												grace_period_expires=grace_period_expires,
												affects_policy_compliance=affects_policy_compliance,
												mitigation_status=mitigation_status,
												mitigation_status_desc=mitigation_status_desc,
												sourcefile=sourcefile,
												line=line,
												sourcefilepath=sourcefilepath,
												scope=scope,
												functionprototype=functionprototype,
												functionrelativelocation=functionrelativelocation)

									except (TypeError) as e:
										self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
										severity = categories['cwe']['staticflaws']['flaw']['@severity']
										categoryname = categories['cwe']['staticflaws']['flaw']['@categoryname']
										count = categories['cwe']['staticflaws']['flaw']['@count']
										issueid = categories['cwe']['staticflaws']['flaw']['@issueid']
										module = categories['cwe']['staticflaws']['flaw']['@module']
										type = categories['cwe']['staticflaws']['flaw']['@type']
										description = categories['cwe']['staticflaws']['flaw']['@description']
										note = categories['cwe']['staticflaws']['flaw']['@note']
										cweid = categories['cwe']['staticflaws']['flaw']['@cweid']
										remediationeffort = categories['cwe']['staticflaws']['flaw']['@remediationeffort']
										exploitLevel = categories['cwe']['staticflaws']['flaw']['@exploitLevel']
										categoryid = categories['cwe']['staticflaws']['flaw']['@categoryid']
										pcirelated = categories['cwe']['staticflaws']['flaw']['@pcirelated']
										date_first_occurrence = categories['cwe']['staticflaws']['flaw']['@date_first_occurrence']
										remediation_status = categories['cwe']['staticflaws']['flaw']['@remediation_status']
										cia_impact = categories['cwe']['staticflaws']['flaw']['@cia_impact']
										grace_period_expires = categories['cwe']['staticflaws']['flaw']['@grace_period_expires']
										affects_policy_compliance = categories['cwe']['staticflaws']['flaw']['@affects_policy_compliance']
										mitigation_status = categories['cwe']['staticflaws']['flaw']['@mitigation_status']
										mitigation_status_desc = categories['cwe']['staticflaws']['flaw']['@mitigation_status_desc']
										sourcefile = categories['cwe']['staticflaws']['flaw']['@sourcefile']
										line = categories['cwe']['staticflaws']['flaw']['@line']
										sourcefilepath = categories['cwe']['staticflaws']['flaw']['@sourcefilepath']
										scope = categories['cwe']['staticflaws']['flaw']['@scope']
										functionprototype = categories['cwe']['staticflaws']['flaw']['@functionprototype']
										functionrelativelocation = categories['cwe']['staticflaws']['flaw']['@functionrelativelocation']

										self.output(
											app_report_format_version=app_report_format_version,
											app_account_id=app_account_id,
											app_app_name=app_app_name,
											app_app_id=app_app_id,
											app_analysis_id=app_analysis_id,
											app_static_analysis_unit_id=app_static_analysis_unit_id,
											app_sandbox_id=app_sandbox_id,
											app_first_build_submitted_date=app_first_build_submitted_date,
											app_version=app_version,
											app_build_id=app_build_id,
											app_submitter=app_submitter,
											app_platform=app_platform,
											app_assurance_level=app_assurance_level,
											app_business_criticality=app_business_criticality,
											app_generation_date=app_generation_date,
											app_veracode_level=app_veracode_level,
											app_total_flaws=app_total_flaws,
											app_flaws_not_mitigated=app_flaws_not_mitigated,
											app_teams=app_teams,
											app_life_cycle_stage=app_life_cycle_stage,
											app_planned_deployment_date=app_planned_deployment_date,
											app_last_update_time=app_last_update_time,
											app_is_latest_build=app_is_latest_build,
											app_policy_name=app_policy_name,
											app_policy_version=app_policy_version,
											app_policy_compliance_status=app_policy_compliance_status,
											app_policy_rules_status=app_policy_rules_status,
											app_grace_period_expired=app_grace_period_expired,
											app_scan_overdue=app_scan_overdue,
											app_business_owner=app_business_owner,
											app_business_unit=app_business_unit,
											app_tags=app_tags,
											app_legacy_scan_engine=app_legacy_scan_engine,
											analysis_rating=analysis_rating,
											analysis_score=analysis_score,
											analysis_submitted_date=analysis_submitted_date,
											analysis_published_date=analysis_published_date,
											analysis_version=analysis_version,
											analysis_next_scan_due=analysis_next_scan_due,
											analysis_analysis_size_bytes=analysis_analysis_size_bytes,
											analysis_engine_version=analysis_engine_version,
											status_new=status_new,
											status_reopen=status_reopen,
											status_open=status_open,
											status_cannot_reproduce=status_cannot_reproduce,
											status_fixed=status_fixed,
											status_total=status_total,
											status_not_mitigated=status_not_mitigated,
											status_sev_1_change=status_sev_1_change,
											status_sev_2_change=status_sev_2_change,
											status_sev_3_change=status_sev_3_change,
											status_sev_4_change=status_sev_4_change,
											status_sev_5_change=status_sev_5_change,
											desc_list=desc_list,
											rem_list=rem_list,
											cwename=cwename,
											owasp=owasp,
											owasp2013=owasp2013,
											sans=sans,
											owaspmobile=owaspmobile,
											severity=severity,
											categoryname=categoryname,
											count=count,
											issueid=issueid,
											module=module,
											type=type,
											description=description,
											note=note,
											cweid=cweid,
											remediationeffort=remediationeffort,
											exploitLevel=exploitLevel,
											categoryid=categoryid,
											pcirelated=pcirelated,
											date_first_occurrence=date_first_occurrence,
											remediation_status=remediation_status,
											cia_impact=cia_impact,
											grace_period_expires=grace_period_expires,
											affects_policy_compliance=affects_policy_compliance,
											mitigation_status=mitigation_status,
											mitigation_status_desc=mitigation_status_desc,
											sourcefile=sourcefile,
											line=line,
											sourcefilepath=sourcefilepath,
											scope=scope,
											functionprototype=functionprototype,
											functionrelativelocation=functionrelativelocation)

						except (TypeError) as e:
							self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
							categoryid = vulns['category']['@categoryid']
							categoryname = vulns['category']['@categoryname']
							pcirelated = vulns['category']['@pcirelated']
							desc_list = []
							try:
								for desc in vulns['category']['desc']['para']:
									desc_list.append(desc['@text'])
							except (TypeError) as e:
								self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
								desc_list.append(vulns['category']['desc']['para']['@text'])

							rem_list = []
							try:
								for recommendations in vulns['category']['recommendations']['para']:
									rem_list.append(recommendations['@text'])
							except (TypeError) as e:
								self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
								rem_list.append(vulns['category']['recommendations']['para']['@text'])

							cweid = vulns['category']['cwe']['@cweid']
							cwename = vulns['category']['cwe']['@cwename']
							pcirelated = vulns['category']['cwe']['@pcirelated']

							try:
								owasp = vulns['category']['cwe']['@owasp']
							except (KeyError) as e:
								self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
								owasp = "Null"

							try:
								owasp2013 = vulns['category']['cwe']['@owasp2013']
							except (KeyError) as e:
								self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
								owasp2013 = "Null"

							try:
								sans = vulns['category']['cwe']['@sans']
							except (KeyError) as e:
								self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
								sans = "Null"

							try:
								owaspmobile = vulns['category']['cwe']['@owaspmobile']
							except (KeyError) as e:
								self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
								owaspmobile = "Null"

							try:
								for staticflaws in vulns['category']['cwe']['staticflaws']['flaw']:
									severity = staticflaws['@severity']
									categoryname = staticflaws['@categoryname']
									count = staticflaws['@count']
									issueid = staticflaws['@issueid']
									module = staticflaws['@module']
									type = staticflaws['@type']
									description = staticflaws['@description']
									note = staticflaws['@note']
									cweid = staticflaws['@cweid']
									remediationeffort = staticflaws['@remediationeffort']
									exploitLevel = staticflaws['@exploitLevel']
									categoryid = staticflaws['@categoryid']
									pcirelated = staticflaws['@pcirelated']
									date_first_occurrence = staticflaws['@date_first_occurrence']
									remediation_status = staticflaws['@remediation_status']
									cia_impact = staticflaws['@cia_impact']
									grace_period_expires = staticflaws['@grace_period_expires']
									affects_policy_compliance = staticflaws['@affects_policy_compliance']
									mitigation_status = staticflaws['@mitigation_status']
									mitigation_status_desc = staticflaws['@mitigation_status_desc']
									sourcefile = staticflaws['@sourcefile']
									line = staticflaws['@line']
									sourcefilepath = staticflaws['@sourcefilepath']
									scope = staticflaws['@scope']
									functionprototype = staticflaws['@functionprototype']
									functionrelativelocation = staticflaws['@functionrelativelocation']

									self.output(
										app_report_format_version=app_report_format_version,
										app_account_id=app_account_id,
										app_app_name=app_app_name,
										app_app_id=app_app_id,
										app_analysis_id=app_analysis_id,
										app_static_analysis_unit_id=app_static_analysis_unit_id,
										app_sandbox_id=app_sandbox_id,
										app_first_build_submitted_date=app_first_build_submitted_date,
										app_version=app_version,
										app_build_id=app_build_id,
										app_submitter=app_submitter,
										app_platform=app_platform,
										app_assurance_level=app_assurance_level,
										app_business_criticality=app_business_criticality,
										app_generation_date=app_generation_date,
										app_veracode_level=app_veracode_level,
										app_total_flaws=app_total_flaws,
										app_flaws_not_mitigated=app_flaws_not_mitigated,
										app_teams=app_teams,
										app_life_cycle_stage=app_life_cycle_stage,
										app_planned_deployment_date=app_planned_deployment_date,
										app_last_update_time=app_last_update_time,
										app_is_latest_build=app_is_latest_build,
										app_policy_name=app_policy_name,
										app_policy_version=app_policy_version,
										app_policy_compliance_status=app_policy_compliance_status,
										app_policy_rules_status=app_policy_rules_status,
										app_grace_period_expired=app_grace_period_expired,
										app_scan_overdue=app_scan_overdue,
										app_business_owner=app_business_owner,
										app_business_unit=app_business_unit,
										app_tags=app_tags,
										app_legacy_scan_engine=app_legacy_scan_engine,
										analysis_rating=analysis_rating,
										analysis_score=analysis_score,
										analysis_submitted_date=analysis_submitted_date,
										analysis_published_date=analysis_published_date,
										analysis_version=analysis_version,
										analysis_next_scan_due=analysis_next_scan_due,
										analysis_analysis_size_bytes=analysis_analysis_size_bytes,
										analysis_engine_version=analysis_engine_version,
										status_new=status_new,
										status_reopen=status_reopen,
										status_open=status_open,
										status_cannot_reproduce=status_cannot_reproduce,
										status_fixed=status_fixed,
										status_total=status_total,
										status_not_mitigated=status_not_mitigated,
										status_sev_1_change=status_sev_1_change,
										status_sev_2_change=status_sev_2_change,
										status_sev_3_change=status_sev_3_change,
										status_sev_4_change=status_sev_4_change,
										status_sev_5_change=status_sev_5_change,
										desc_list=desc_list,
										rem_list=rem_list,
										cwename=cwename,
										owasp=owasp,
										owasp2013=owasp2013,
										sans=sans,
										owaspmobile=owaspmobile,
										severity=severity,
										categoryname=categoryname,
										count=count,
										issueid=issueid,
										module=module,
										type=type,
										description=description,
										note=note,
										cweid=cweid,
										remediationeffort=remediationeffort,
										exploitLevel=exploitLevel,
										categoryid=categoryid,
										pcirelated=pcirelated,
										date_first_occurrence=date_first_occurrence,
										remediation_status=remediation_status,
										cia_impact=cia_impact,
										grace_period_expires=grace_period_expires,
										affects_policy_compliance=affects_policy_compliance,
										mitigation_status=mitigation_status,
										mitigation_status_desc=mitigation_status_desc,
										sourcefile=sourcefile,
										line=line,
										sourcefilepath=sourcefilepath,
										scope=scope,
										functionprototype=functionprototype,
										functionrelativelocation=functionrelativelocation)

							except (TypeError) as e:
								self.logger.debug("6: {e} not found, I'm starting exception".format(e=e))
								severity = vulns['category']['cwe']['staticflaws']['flaw']['@severity']
								categoryname = vulns['category']['cwe']['staticflaws']['flaw']['@categoryname']
								count = vulns['category']['cwe']['staticflaws']['flaw']['@count']
								issueid = vulns['category']['cwe']['staticflaws']['flaw']['@issueid']
								module = vulns['category']['cwe']['staticflaws']['flaw']['@module']
								type = vulns['category']['cwe']['staticflaws']['flaw']['@type']
								description = vulns['category']['cwe']['staticflaws']['flaw']['@description']
								note = vulns['category']['cwe']['staticflaws']['flaw']['@note']
								cweid = vulns['category']['cwe']['staticflaws']['flaw']['@cweid']
								remediationeffort = vulns['category']['cwe']['staticflaws']['flaw']['@remediationeffort']
								exploitLevel = vulns['category']['cwe']['staticflaws']['flaw']['@exploitLevel']
								categoryid = vulns['category']['cwe']['staticflaws']['flaw']['@categoryid']
								pcirelated = vulns['category']['cwe']['staticflaws']['flaw']['@pcirelated']
								date_first_occurrence = vulns['category']['cwe']['staticflaws']['flaw']['@date_first_occurrence']
								remediation_status = vulns['category']['cwe']['staticflaws']['flaw']['@remediation_status']
								cia_impact = vulns['category']['cwe']['staticflaws']['flaw']['@cia_impact']
								grace_period_expires = vulns['category']['cwe']['staticflaws']['flaw']['@grace_period_expires']
								affects_policy_compliance = vulns['category']['cwe']['staticflaws']['flaw']['@affects_policy_compliance']
								mitigation_status = vulns['category']['cwe']['staticflaws']['flaw']['@mitigation_status']
								mitigation_status_desc = vulns['category']['cwe']['staticflaws']['flaw']['@mitigation_status_desc']
								sourcefile = vulns['category']['cwe']['staticflaws']['flaw']['@sourcefile']
								line = vulns['category']['cwe']['staticflaws']['flaw']['@line']
								sourcefilepath = vulns['category']['cwe']['staticflaws']['flaw']['@sourcefilepath']
								scope = vulns['category']['cwe']['staticflaws']['flaw']['@scope']
								functionprototype = vulns['category']['cwe']['staticflaws']['flaw']['@functionprototype']
								functionrelativelocation = vulns['category']['cwe']['staticflaws']['flaw']['@functionrelativelocation']

								self.output(
									app_report_format_version=app_report_format_version,
									app_account_id=app_account_id,
									app_app_name=app_app_name,
									app_app_id=app_app_id,
									app_analysis_id=app_analysis_id,
									app_static_analysis_unit_id=app_static_analysis_unit_id,
									app_sandbox_id=app_sandbox_id,
									app_first_build_submitted_date=app_first_build_submitted_date,
									app_version=app_version,
									app_build_id=app_build_id,
									app_submitter=app_submitter,
									app_platform=app_platform,
									app_assurance_level=app_assurance_level,
									app_business_criticality=app_business_criticality,
									app_generation_date=app_generation_date,
									app_veracode_level=app_veracode_level,
									app_total_flaws=app_total_flaws,
									app_flaws_not_mitigated=app_flaws_not_mitigated,
									app_teams=app_teams,
									app_life_cycle_stage=app_life_cycle_stage,
									app_planned_deployment_date=app_planned_deployment_date,
									app_last_update_time=app_last_update_time,
									app_is_latest_build=app_is_latest_build,
									app_policy_name=app_policy_name,
									app_policy_version=app_policy_version,
									app_policy_compliance_status=app_policy_compliance_status,
									app_policy_rules_status=app_policy_rules_status,
									app_grace_period_expired=app_grace_period_expired,
									app_scan_overdue=app_scan_overdue,
									app_business_owner=app_business_owner,
									app_business_unit=app_business_unit,
									app_tags=app_tags,
									app_legacy_scan_engine=app_legacy_scan_engine,
									analysis_rating=analysis_rating,
									analysis_score=analysis_score,
									analysis_submitted_date=analysis_submitted_date,
									analysis_published_date=analysis_published_date,
									analysis_version=analysis_version,
									analysis_next_scan_due=analysis_next_scan_due,
									analysis_analysis_size_bytes=analysis_analysis_size_bytes,
									analysis_engine_version=analysis_engine_version,
									status_new=status_new,
									status_reopen=status_reopen,
									status_open=status_open,
									status_cannot_reproduce=status_cannot_reproduce,
									status_fixed=status_fixed,
									status_total=status_total,
									status_not_mitigated=status_not_mitigated,
									status_sev_1_change=status_sev_1_change,
									status_sev_2_change=status_sev_2_change,
									status_sev_3_change=status_sev_3_change,
									status_sev_4_change=status_sev_4_change,
									status_sev_5_change=status_sev_5_change,
									desc_list=desc_list,
									rem_list=rem_list,
									cwename=cwename,
									owasp=owasp,
									owasp2013=owasp2013,
									sans=sans,
									owaspmobile=owaspmobile,
									severity=severity,
									categoryname=categoryname,
									count=count,
									issueid=issueid,
									module=module,
									type=type,
									description=description,
									note=note,
									cweid=cweid,
									remediationeffort=remediationeffort,
									exploitLevel=exploitLevel,
									categoryid=categoryid,
									pcirelated=pcirelated,
									date_first_occurrence=date_first_occurrence,
									remediation_status=remediation_status,
									cia_impact=cia_impact,
									grace_period_expires=grace_period_expires,
									affects_policy_compliance=affects_policy_compliance,
									mitigation_status=mitigation_status,
									mitigation_status_desc=mitigation_status_desc,
									sourcefile=sourcefile,
									line=line,
									sourcefilepath=sourcefilepath,
									scope=scope,
									functionprototype=functionprototype,
									functionrelativelocation=functionrelativelocation)

					else:
						self.logger.debug('The value of categories is different from 6 this deal is simpler.')
						for categories in vulns['category']:
							categoryid = categories['@categoryid']
							categoryname = categories['@categoryname']
							pcirelated = categories['@pcirelated']

							desc_list = []
							try:
								for desc in categories['desc']['para']:
									desc_list.append(desc['@text'])
							except (TypeError) as e:
								self.logger.debug("{e} not found, I'm starting exception".format(e=e))
								desc_list.append(categories['desc']['para']['@text'])

							rem_list = []
							try:
								for recommendations in categories['recommendations']['para']:
									rem_list.append(recommendations['@text'])
							except (TypeError) as e:
								self.logger.debug("{e} not found, I'm starting exception".format(e=e))
								rem_list.append(categories['recommendations']['para']['@text'])

							try:
								for cwe in categories['cwe']:
									cweid = cwe['@cweid']
									cwename = cwe['@cwename']
									pcirelated = cwe['@pcirelated']

									try:
										owasp = cwe['@owasp']
									except (KeyError) as e:
										self.logger.debug("{e} not found, I'm starting exception".format(e=e))
										owasp = "Null"
									try:
										owasp2013 = cwe['@owasp2013']
									except (KeyError) as e:
										self.logger.debug("{e} not found, I'm starting exception".format(e=e))
										owasp2013 = "Null"
									try:
										sans = cwe['@sans']
									except (KeyError) as e:
										self.logger.debug("{e} not found, I'm starting exception".format(e=e))
										sans = "Null"
									try:
										owaspmobile = cwe['@owaspmobile']
									except (KeyError) as e:
										self.logger.debug("{e} not found, I'm starting exception".format(e=e))
										owaspmobile = "Null"

									try:
										for staticflaws in cwe['staticflaws']['flaw']:
											severity = staticflaws['@severity']
											categoryname = staticflaws['@categoryname']
											count = staticflaws['@count']
											issueid = staticflaws['@issueid']
											module = staticflaws['@module']
											type = staticflaws['@type']
											description = staticflaws['@description']
											note = staticflaws['@note']
											cweid = staticflaws['@cweid']
											remediationeffort = staticflaws['@remediationeffort']
											exploitLevel = staticflaws['@exploitLevel']
											categoryid = staticflaws['@categoryid']
											pcirelated = staticflaws['@pcirelated']
											date_first_occurrence = staticflaws['@date_first_occurrence']
											remediation_status = staticflaws['@remediation_status']
											cia_impact = staticflaws['@cia_impact']
											grace_period_expires = staticflaws['@grace_period_expires']
											affects_policy_compliance = staticflaws['@affects_policy_compliance']
											mitigation_status = staticflaws['@mitigation_status']
											mitigation_status_desc = staticflaws['@mitigation_status_desc']
											sourcefile = staticflaws['@sourcefile']
											line = staticflaws['@line']
											sourcefilepath = staticflaws['@sourcefilepath']
											scope = staticflaws['@scope']
											functionprototype = staticflaws['@functionprototype']
											functionrelativelocation = staticflaws['@functionrelativelocation']

											self.output(
												app_report_format_version=app_report_format_version,
												app_account_id=app_account_id,
												app_app_name=app_app_name,
												app_app_id=app_app_id,
												app_analysis_id=app_analysis_id,
												app_static_analysis_unit_id=app_static_analysis_unit_id,
												app_sandbox_id=app_sandbox_id,
												app_first_build_submitted_date=app_first_build_submitted_date,
												app_version=app_version,
												app_build_id=app_build_id,
												app_submitter=app_submitter,
												app_platform=app_platform,
												app_assurance_level=app_assurance_level,
												app_business_criticality=app_business_criticality,
												app_generation_date=app_generation_date,
												app_veracode_level=app_veracode_level,
												app_total_flaws=app_total_flaws,
												app_flaws_not_mitigated=app_flaws_not_mitigated,
												app_teams=app_teams,
												app_life_cycle_stage=app_life_cycle_stage,
												app_planned_deployment_date=app_planned_deployment_date,
												app_last_update_time=app_last_update_time,
												app_is_latest_build=app_is_latest_build,
												app_policy_name=app_policy_name,
												app_policy_version=app_policy_version,
												app_policy_compliance_status=app_policy_compliance_status,
												app_policy_rules_status=app_policy_rules_status,
												app_grace_period_expired=app_grace_period_expired,
												app_scan_overdue=app_scan_overdue,
												app_business_owner=app_business_owner,
												app_business_unit=app_business_unit,
												app_tags=app_tags,
												app_legacy_scan_engine=app_legacy_scan_engine,
												analysis_rating=analysis_rating,
												analysis_score=analysis_score,
												analysis_submitted_date=analysis_submitted_date,
												analysis_published_date=analysis_published_date,
												analysis_version=analysis_version,
												analysis_next_scan_due=analysis_next_scan_due,
												analysis_analysis_size_bytes=analysis_analysis_size_bytes,
												analysis_engine_version=analysis_engine_version,
												status_new=status_new,
												status_reopen=status_reopen,
												status_open=status_open,
												status_cannot_reproduce=status_cannot_reproduce,
												status_fixed=status_fixed,
												status_total=status_total,
												status_not_mitigated=status_not_mitigated,
												status_sev_1_change=status_sev_1_change,
												status_sev_2_change=status_sev_2_change,
												status_sev_3_change=status_sev_3_change,
												status_sev_4_change=status_sev_4_change,
												status_sev_5_change=status_sev_5_change,
												desc_list=desc_list,
												rem_list=rem_list,
												cwename=cwename,
												owasp=owasp,
												owasp2013=owasp2013,
												sans=sans,
												owaspmobile=owaspmobile,
												severity=severity,
												categoryname=categoryname,
												count=count,
												issueid=issueid,
												module=module,
												type=type,
												description=description,
												note=note,
												cweid=cweid,
												remediationeffort=remediationeffort,
												exploitLevel=exploitLevel,
												categoryid=categoryid,
												pcirelated=pcirelated,
												date_first_occurrence=date_first_occurrence,
												remediation_status=remediation_status,
												cia_impact=cia_impact,
												grace_period_expires=grace_period_expires,
												affects_policy_compliance=affects_policy_compliance,
												mitigation_status=mitigation_status,
												mitigation_status_desc=mitigation_status_desc,
												sourcefile=sourcefile,
												line=line,
												sourcefilepath=sourcefilepath,
												scope=scope,
												functionprototype=functionprototype,
												functionrelativelocation=functionrelativelocation)

									except (TypeError) as e:
										self.logger.debug("{e} not found, I'm starting exception".format(e=e))
										severity = cwe['staticflaws']['flaw']['@severity']
										categoryname = cwe['staticflaws']['flaw']['@categoryname']
										count = cwe['staticflaws']['flaw']['@count']
										issueid = cwe['staticflaws']['flaw']['@issueid']
										module = cwe['staticflaws']['flaw']['@module']
										type = cwe['staticflaws']['flaw']['@type']
										description = cwe['staticflaws']['flaw']['@description']
										note = cwe['staticflaws']['flaw']['@note']
										cweid = cwe['staticflaws']['flaw']['@cweid']
										remediationeffort = cwe['staticflaws']['flaw']['@remediationeffort']
										exploitLevel = cwe['staticflaws']['flaw']['@exploitLevel']
										categoryid = cwe['staticflaws']['flaw']['@categoryid']
										pcirelated = cwe['staticflaws']['flaw']['@pcirelated']
										date_first_occurrence = cwe['staticflaws']['flaw']['@date_first_occurrence']
										remediation_status = cwe['staticflaws']['flaw']['@remediation_status']
										cia_impact = cwe['staticflaws']['flaw']['@cia_impact']
										grace_period_expires = cwe['staticflaws']['flaw']['@grace_period_expires']
										affects_policy_compliance = cwe['staticflaws']['flaw']['@affects_policy_compliance']
										mitigation_status = cwe['staticflaws']['flaw']['@mitigation_status']
										mitigation_status_desc = cwe['staticflaws']['flaw']['@mitigation_status_desc']
										sourcefile = cwe['staticflaws']['flaw']['@sourcefile']
										line = cwe['staticflaws']['flaw']['@line']
										sourcefilepath = cwe['staticflaws']['flaw']['@sourcefilepath']
										scope = cwe['staticflaws']['flaw']['@scope']
										functionprototype = cwe['staticflaws']['flaw']['@functionprototype']
										functionrelativelocation = cwe['staticflaws']['flaw']['@functionrelativelocation']

										self.output(
											app_report_format_version=app_report_format_version,
											app_account_id=app_account_id,
											app_app_name=app_app_name,
											app_app_id=app_app_id,
											app_analysis_id=app_analysis_id,
											app_static_analysis_unit_id=app_static_analysis_unit_id,
											app_sandbox_id=app_sandbox_id,
											app_first_build_submitted_date=app_first_build_submitted_date,
											app_version=app_version,
											app_build_id=app_build_id,
											app_submitter=app_submitter,
											app_platform=app_platform,
											app_assurance_level=app_assurance_level,
											app_business_criticality=app_business_criticality,
											app_generation_date=app_generation_date,
											app_veracode_level=app_veracode_level,
											app_total_flaws=app_total_flaws,
											app_flaws_not_mitigated=app_flaws_not_mitigated,
											app_teams=app_teams,
											app_life_cycle_stage=app_life_cycle_stage,
											app_planned_deployment_date=app_planned_deployment_date,
											app_last_update_time=app_last_update_time,
											app_is_latest_build=app_is_latest_build,
											app_policy_name=app_policy_name,
											app_policy_version=app_policy_version,
											app_policy_compliance_status=app_policy_compliance_status,
											app_policy_rules_status=app_policy_rules_status,
											app_grace_period_expired=app_grace_period_expired,
											app_scan_overdue=app_scan_overdue,
											app_business_owner=app_business_owner,
											app_business_unit=app_business_unit,
											app_tags=app_tags,
											app_legacy_scan_engine=app_legacy_scan_engine,
											analysis_rating=analysis_rating,
											analysis_score=analysis_score,
											analysis_submitted_date=analysis_submitted_date,
											analysis_published_date=analysis_published_date,
											analysis_version=analysis_version,
											analysis_next_scan_due=analysis_next_scan_due,
											analysis_analysis_size_bytes=analysis_analysis_size_bytes,
											analysis_engine_version=analysis_engine_version,
											status_new=status_new,
											status_reopen=status_reopen,
											status_open=status_open,
											status_cannot_reproduce=status_cannot_reproduce,
											status_fixed=status_fixed,
											status_total=status_total,
											status_not_mitigated=status_not_mitigated,
											status_sev_1_change=status_sev_1_change,
											status_sev_2_change=status_sev_2_change,
											status_sev_3_change=status_sev_3_change,
											status_sev_4_change=status_sev_4_change,
											status_sev_5_change=status_sev_5_change,
											desc_list=desc_list,
											rem_list=rem_list,
											cwename=cwename,
											owasp=owasp,
											owasp2013=owasp2013,
											sans=sans,
											owaspmobile=owaspmobile,
											severity=severity,
											categoryname=categoryname,
											count=count,
											issueid=issueid,
											module=module,
											type=type,
											description=description,
											note=note,
											cweid=cweid,
											remediationeffort=remediationeffort,
											exploitLevel=exploitLevel,
											categoryid=categoryid,
											pcirelated=pcirelated,
											date_first_occurrence=date_first_occurrence,
											remediation_status=remediation_status,
											cia_impact=cia_impact,
											grace_period_expires=grace_period_expires,
											affects_policy_compliance=affects_policy_compliance,
											mitigation_status=mitigation_status,
											mitigation_status_desc=mitigation_status_desc,
											sourcefile=sourcefile,
											line=line,
											sourcefilepath=sourcefilepath,
											scope=scope,
											functionprototype=functionprototype,
											functionrelativelocation=functionrelativelocation)

							except (TypeError) as e:
								cweid = categories['cwe']['@cweid']
								cwename = categories['cwe']['@cwename']
								pcirelated = categories['cwe']['@pcirelated']
								try:
									owasp = categories['cwe']['@owasp']
								except (KeyError) as e:
									self.logger.debug("{e} not found, I'm starting exception".format(e=e))
									owasp = "Null"
								try:
									owasp2013 = categories['cwe']['@owasp2013']
								except (KeyError) as e:
									self.logger.debug("{e} not found, I'm starting exception".format(e=e))
									owasp2013 = "Null"
								try:
									sans = categories['cwe']['@sans']
								except (KeyError) as e:
									self.logger.debug("{e} not found, I'm starting exception".format(e=e))
									sans = "Null"
								try:
									owaspmobile = categories['cwe']['@owaspmobile']
								except (KeyError) as e:
									self.logger.debug("{e} not found, I'm starting exception".format(e=e))
									owaspmobile = "Null"

								try:
									for staticflaws in categories['cwe']['staticflaws']['flaw']:
										severity = staticflaws['@severity']
										categoryname = staticflaws['@categoryname']
										count = staticflaws['@count']
										issueid = staticflaws['@issueid']
										module = staticflaws['@module']
										type = staticflaws['@type']
										description = staticflaws['@description']
										note = staticflaws['@note']
										cweid = staticflaws['@cweid']
										remediationeffort = staticflaws['@remediationeffort']
										exploitLevel = staticflaws['@exploitLevel']
										categoryid = staticflaws['@categoryid']
										pcirelated = staticflaws['@pcirelated']
										date_first_occurrence = staticflaws['@date_first_occurrence']
										remediation_status = staticflaws['@remediation_status']
										cia_impact = staticflaws['@cia_impact']
										grace_period_expires = staticflaws['@grace_period_expires']
										affects_policy_compliance = staticflaws['@affects_policy_compliance']
										mitigation_status = staticflaws['@mitigation_status']
										mitigation_status_desc = staticflaws['@mitigation_status_desc']
										sourcefile = staticflaws['@sourcefile']
										line = staticflaws['@line']
										sourcefilepath = staticflaws['@sourcefilepath']
										scope = staticflaws['@scope']
										functionprototype = staticflaws['@functionprototype']
										functionrelativelocation = staticflaws['@functionrelativelocation']

										self.output(
											app_report_format_version=app_report_format_version,
											app_account_id=app_account_id,
											app_app_name=app_app_name,
											app_app_id=app_app_id,
											app_analysis_id=app_analysis_id,
											app_static_analysis_unit_id=app_static_analysis_unit_id,
											app_sandbox_id=app_sandbox_id,
											app_first_build_submitted_date=app_first_build_submitted_date,
											app_version=app_version,
											app_build_id=app_build_id,
											app_submitter=app_submitter,
											app_platform=app_platform,
											app_assurance_level=app_assurance_level,
											app_business_criticality=app_business_criticality,
											app_generation_date=app_generation_date,
											app_veracode_level=app_veracode_level,
											app_total_flaws=app_total_flaws,
											app_flaws_not_mitigated=app_flaws_not_mitigated,
											app_teams=app_teams,
											app_life_cycle_stage=app_life_cycle_stage,
											app_planned_deployment_date=app_planned_deployment_date,
											app_last_update_time=app_last_update_time,
											app_is_latest_build=app_is_latest_build,
											app_policy_name=app_policy_name,
											app_policy_version=app_policy_version,
											app_policy_compliance_status=app_policy_compliance_status,
											app_policy_rules_status=app_policy_rules_status,
											app_grace_period_expired=app_grace_period_expired,
											app_scan_overdue=app_scan_overdue,
											app_business_owner=app_business_owner,
											app_business_unit=app_business_unit,
											app_tags=app_tags,
											app_legacy_scan_engine=app_legacy_scan_engine,
											analysis_rating=analysis_rating,
											analysis_score=analysis_score,
											analysis_submitted_date=analysis_submitted_date,
											analysis_published_date=analysis_published_date,
											analysis_version=analysis_version,
											analysis_next_scan_due=analysis_next_scan_due,
											analysis_analysis_size_bytes=analysis_analysis_size_bytes,
											analysis_engine_version=analysis_engine_version,
											status_new=status_new,
											status_reopen=status_reopen,
											status_open=status_open,
											status_cannot_reproduce=status_cannot_reproduce,
											status_fixed=status_fixed,
											status_total=status_total,
											status_not_mitigated=status_not_mitigated,
											status_sev_1_change=status_sev_1_change,
											status_sev_2_change=status_sev_2_change,
											status_sev_3_change=status_sev_3_change,
											status_sev_4_change=status_sev_4_change,
											status_sev_5_change=status_sev_5_change,
											desc_list=desc_list,
											rem_list=rem_list,
											cwename=cwename,
											owasp=owasp,
											owasp2013=owasp2013,
											sans=sans,
											owaspmobile=owaspmobile,
											severity=severity,
											categoryname=categoryname,
											count=count,
											issueid=issueid,
											module=module,
											type=type,
											description=description,
											note=note,
											cweid=cweid,
											remediationeffort=remediationeffort,
											exploitLevel=exploitLevel,
											categoryid=categoryid,
											pcirelated=pcirelated,
											date_first_occurrence=date_first_occurrence,
											remediation_status=remediation_status,
											cia_impact=cia_impact,
											grace_period_expires=grace_period_expires,
											affects_policy_compliance=affects_policy_compliance,
											mitigation_status=mitigation_status,
											mitigation_status_desc=mitigation_status_desc,
											sourcefile=sourcefile,
											line=line,
											sourcefilepath=sourcefilepath,
											scope=scope,
											functionprototype=functionprototype,
											functionrelativelocation=functionrelativelocation)

								except (TypeError) as e:
									self.logger.debug("{e} not found, I'm starting exception".format(e=e))
									severity = categories['cwe']['staticflaws']['flaw']['@severity']
									categoryname = categories['cwe']['staticflaws']['flaw']['@categoryname']
									count = categories['cwe']['staticflaws']['flaw']['@count']
									issueid = categories['cwe']['staticflaws']['flaw']['@issueid']
									module = categories['cwe']['staticflaws']['flaw']['@module']
									type = categories['cwe']['staticflaws']['flaw']['@type']
									description = categories['cwe']['staticflaws']['flaw']['@description']
									note = categories['cwe']['staticflaws']['flaw']['@note']
									cweid = categories['cwe']['staticflaws']['flaw']['@cweid']
									remediationeffort = categories['cwe']['staticflaws']['flaw']['@remediationeffort']
									exploitLevel = categories['cwe']['staticflaws']['flaw']['@exploitLevel']
									categoryid = categories['cwe']['staticflaws']['flaw']['@categoryid']
									pcirelated = categories['cwe']['staticflaws']['flaw']['@pcirelated']
									date_first_occurrence = categories['cwe']['staticflaws']['flaw']['@date_first_occurrence']
									remediation_status = categories['cwe']['staticflaws']['flaw']['@remediation_status']
									cia_impact = categories['cwe']['staticflaws']['flaw']['@cia_impact']
									grace_period_expires = categories['cwe']['staticflaws']['flaw']['@grace_period_expires']
									affects_policy_compliance = categories['cwe']['staticflaws']['flaw']['@affects_policy_compliance']
									mitigation_status = categories['cwe']['staticflaws']['flaw']['@mitigation_status']
									mitigation_status_desc = categories['cwe']['staticflaws']['flaw']['@mitigation_status_desc']
									sourcefile = categories['cwe']['staticflaws']['flaw']['@sourcefile']
									line = categories['cwe']['staticflaws']['flaw']['@line']
									sourcefilepath = categories['cwe']['staticflaws']['flaw']['@sourcefilepath']
									scope = categories['cwe']['staticflaws']['flaw']['@scope']
									functionprototype = categories['cwe']['staticflaws']['flaw']['@functionprototype']
									functionrelativelocation = categories['cwe']['staticflaws']['flaw']['@functionrelativelocation']

									self.output(
										app_report_format_version=app_report_format_version,
										app_account_id=app_account_id,
										app_app_name=app_app_name,
										app_app_id=app_app_id,
										app_analysis_id=app_analysis_id,
										app_static_analysis_unit_id=app_static_analysis_unit_id,
										app_sandbox_id=app_sandbox_id,
										app_first_build_submitted_date=app_first_build_submitted_date,
										app_version=app_version,
										app_build_id=app_build_id,
										app_submitter=app_submitter,
										app_platform=app_platform,
										app_assurance_level=app_assurance_level,
										app_business_criticality=app_business_criticality,
										app_generation_date=app_generation_date,
										app_veracode_level=app_veracode_level,
										app_total_flaws=app_total_flaws,
										app_flaws_not_mitigated=app_flaws_not_mitigated,
										app_teams=app_teams,
										app_life_cycle_stage=app_life_cycle_stage,
										app_planned_deployment_date=app_planned_deployment_date,
										app_last_update_time=app_last_update_time,
										app_is_latest_build=app_is_latest_build,
										app_policy_name=app_policy_name,
										app_policy_version=app_policy_version,
										app_policy_compliance_status=app_policy_compliance_status,
										app_policy_rules_status=app_policy_rules_status,
										app_grace_period_expired=app_grace_period_expired,
										app_scan_overdue=app_scan_overdue,
										app_business_owner=app_business_owner,
										app_business_unit=app_business_unit,
										app_tags=app_tags,
										app_legacy_scan_engine=app_legacy_scan_engine,
										analysis_rating=analysis_rating,
										analysis_score=analysis_score,
										analysis_submitted_date=analysis_submitted_date,
										analysis_published_date=analysis_published_date,
										analysis_version=analysis_version,
										analysis_next_scan_due=analysis_next_scan_due,
										analysis_analysis_size_bytes=analysis_analysis_size_bytes,
										analysis_engine_version=analysis_engine_version,
										status_new=status_new,
										status_reopen=status_reopen,
										status_open=status_open,
										status_cannot_reproduce=status_cannot_reproduce,
										status_fixed=status_fixed,
										status_total=status_total,
										status_not_mitigated=status_not_mitigated,
										status_sev_1_change=status_sev_1_change,
										status_sev_2_change=status_sev_2_change,
										status_sev_3_change=status_sev_3_change,
										status_sev_4_change=status_sev_4_change,
										status_sev_5_change=status_sev_5_change,
										desc_list=desc_list,
										rem_list=rem_list,
										cwename=cwename,
										owasp=owasp,
										owasp2013=owasp2013,
										sans=sans,
										owaspmobile=owaspmobile,
										severity=severity,
										categoryname=categoryname,
										count=count,
										issueid=issueid,
										module=module,
										type=type,
										description=description,
										note=note,
										cweid=cweid,
										remediationeffort=remediationeffort,
										exploitLevel=exploitLevel,
										categoryid=categoryid,
										pcirelated=pcirelated,
										date_first_occurrence=date_first_occurrence,
										remediation_status=remediation_status,
										cia_impact=cia_impact,
										grace_period_expires=grace_period_expires,
										affects_policy_compliance=affects_policy_compliance,
										mitigation_status=mitigation_status,
										mitigation_status_desc=mitigation_status_desc,
										sourcefile=sourcefile,
										line=line,
										sourcefilepath=sourcefilepath,
										scope=scope,
										functionprototype=functionprototype,
										functionrelativelocation=functionrelativelocation)

class veracode:
	def __init__(self):
		logging.basicConfig(
				level=logging.INFO,
				format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
				datefmt='%Y-%m-%d %H:%M:%S',
		)
		self.logger = logging.getLogger('Start API Veracode XML')

	@property
	def start(self):
		parser = argparse.ArgumentParser()
		parser.add_argument('-c', '--config', help='The directory of the settings file, in Yaml format.',
						   action='store', dest = 'config')
		parser.add_argument('-o', '--output', help='API Exit Type.',
						   action='store', dest = 'output')
		args = parser.parse_args()

		self.logger.info('Getting information from the settings file.')

		with open(args.config, 'r') as stream:
			data = yaml.load(stream,  Loader=yaml.FullLoader)
			database_path = data.get('database_path', '')
			database_name = data.get('database_name', '')
			save_log_dir = data.get('save_log_dir', '')
			user = data.get('user', '')
			passwd = data.get('passwd', '')
			debug = data.get('debug', '')

		files = ['csv', 'xml', 'json']

		if args.output.lower() in files:
			self.logger.info('Output: {}'.format(args.output))
			self.logger.info('Debug: {}'.format(debug))
			self.logger.info('Path database: {}'.format(database_path))
			self.logger.info('Database name: {}'.format(database_name))
			self.logger.info('Files save path: {}\n'.format(save_log_dir))

			self.logger.info('Verificando diretórios.')
			if not os.path.exists(database_path):
				os.mkdir(database_path)

			if not os.path.exists(save_log_dir):
				os.mkdir(save_log_dir)

			self.logger.info('Starting scans download process.')
			API = XMLAPI(
				database_path=database_path,
				database_name=database_name,
				save_log_dir=save_log_dir,
				user=user,
				passwd=passwd,
				output_file=args.output,
				debug=debug,
			)
			try:
				API.start
			except ExpatError as e:
				self.logger.error('Incorrect username or password, try setting the file again.')
		else:
			self.logger.error('You have entered an output format, which I cannot generate, please check the available ones and choose one.')
			exit(0)



try:
	if __name__ == "__main__":
		veracode = veracode()
		veracode.start
except KeyboardInterrupt:
	print('\nIt looks like the script has been terminated by the user.')
	sys.exit(1)
