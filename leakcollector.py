#!/usr/bin/env python3

__version__="1.0"
from requests import RequestException
from email.utils import getaddresses
from requests import ConnectionError
import requests
import argparse
import time

def haveibeenpwned(account):
	api_key     =   'API HERE!' # Change here!
	user_agent  =   'Custom-User-Agent ROIT!'
	urlAPI = 'https://haveibeenpwned.com/api/v3/breachedaccount/'
	breaches = []	 

	headers = {
			'User-Agent':user_agent,
    		'hibp-api-key': api_key,
		}

	response = requests.get(
			urlAPI + account +'?truncateResponse=false', 
			headers=headers
		)

	if response.status_code == 200:
		data = response.json()	
		for outputdata in data:
			breachname = outputdata['Name']
			breachdate = outputdata['BreachDate']
			if breachname:
				breaches.append({'Name':breachname,'BreachDate':breachdate})
		return(breaches)

	elif response.status_code == 404:
		breaches.append({'Name':"Not Found",'BreachDate':""})
		return(breaches)
	
	else:
		#return ("URL: "+urlAPI+"\n"+checker(response))
		return([])

def checker(respcode):
	try:
		if respcode.status_code == 400:
			return("ERROR!: 400 - Incorrect request: The account does not comply with an acceptable format (it is an empty string)")
		elif respcode.status_code == 401:
			return("ERROR !: 401 - Unauthorized")
		elif respcode.status_code == 403:
			return("ERROR !: 403 - Forbidden - No user agent specified in the request")
		elif respcode.status_code == 404:
			return("ERROR !: 404 - Not found - Account could not be found")
		elif respcode.status_code == 429:
			return("ERROR !: 429 - Speed ​​limit exceeded - Wait a moment to retry\n")
		else:
			return("ERROR !: Unable to connect to the server")
	except RequestException:
		return("ERROR !: Unable to connect to the server")

def pwn_collector(email):
	urlPWNDB	=	'https://pwndb2am4tzkvold.onion.ws/'
	user_agent 	=	'Custom-User-Agent ROIT!'
	username	=	email
	domain		=	'%'
	if "@" in email:
		username = email.split("@")[0]
		domain = email.split("@")[1]
	elif not username:
		username = ''
		domain = email
	elif not "@" in email:
		username = ''
		domain = email

	headers = {
		'User-Agent':user_agent,
		'Referer': urlPWNDB,
	}
	
	data = {
	'luser': username,
	'domain': domain,
	'luseropr': '0',
	'domainopr': '0',
	'submitform': 'em'
	}

	response = requests.post(
		urlPWNDB, 
		headers=headers,
		data=data
	)
	try:
		if response.status_code == 200:
			text = response.text
			return(parse_response(text))
		else:
			#return("URL: "+urlPWNDB+"\n"+str(checker(response)))
			return([])

	except:
		pass

def parse_response(resptext):
    if "Array" not in resptext:
        return None

    leaks = resptext.split("Array")[1:]
    emails = []

    for leak in leaks:
        leaked_email = ''
        domain = ''
        password = ''
        try:
            leaked_email = leak.split("[luser] =>")[1].split("[")[0].strip()
            domain = leak.split("[domain] =>")[1].split("[")[0].strip()
            password = leak.split("[password] =>")[1].split(")")[0].strip()
        except:
            pass
        if leaked_email:
            emails.append({'username': leaked_email, 'domain': domain, 'password': password})
    return emails

def main(emails):
	print("[-] Searching for leaks...")

	pwnresults = []
	arrayaccounts = [] 

	for email in emails:
		leaks = pwn_collector(email.strip())
		if leaks:
			for leak in leaks:
				pwnresults.append(leak)

	for result in pwnresults:
		time.sleep(1)
		username = result.get('username', '')
		domain = result.get('domain', '')
		password = result.get('password', '')
		account = username+"@"+domain+":"+password
		breach= haveibeenpwned(username+"@"+domain)
		arrayaccounts.append({'pwned':account,'breach':breach})

	for breachs in arrayaccounts:
		print("[+] Leak: " + breachs["pwned"])
		for b in breachs["breach"]:
			print("    Breach: " + b["Name"] + " - " + b["BreachDate"])




if __name__ == "__main__":

	parser = argparse.ArgumentParser(prog='leakcollector.py',epilog="Version: {} | Author: pep3,byt3c4t | Blog: https://blog.roit.cl/".format(__version__))
	parser.add_argument("--target", help="Target email/domain to search for leaks.")
	args = parser.parse_args()
	
	emails = []

	if args.target:
		emails.append(args.target)
	else:
		parser.print_help()
		exit(-1)

	try:
		main(emails)
	except Exception as e:
		print("[X] ERROR!: ", e)
