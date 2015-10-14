#!/usr/bin/python

import re
import sys
import os.path
import time
import Queue
import multiprocessing
import json
import urllib

def dumpQueue(queue):
	result = []
	for i in iter(queue.get, 'STOP'):
		result.append(i)
	return result

def checkIP(IP,publicAPIKey,resultQueue):
	# Check whether it is private IP
	# Private IP address range
	# 10.0.0.0 - 10.255.255.255
	# 172.16.0.0 - 172.31.255.255
	# 192.168.0.0 - 192.168.255.255
	IPsplit = IP.split(".")
	if int(IPsplit[0]) == 10 :
		#return "Private IP"
		resultQueue.put(IP + "\tPrivate IP")

	elif (int(IPsplit[0]) == 172) and (16<= int(IPsplit[1]) <= 31) :
		#return "PrivateIP"
		resultQueue.put(IP + "\tPrivate IP")

	elif (int(IPsplit[0]) == 192) and ( int(IPsplit[1]) == 168) :
		#return "PrivateIP"
		resultQueue.put(IP + "\tPrivate IP")
		
	else :
		reputation = ""
		queryResult = {}

		dUrls = {}	#detected_urls
		dDS = {}	#detected_downloaded_samples
		dCS = {}	#detected_communicating_samples
		dRS = {}	#detected_referrer_samples
		count_dUrls = 0	#detected_urls
		count_dDS = 0	#detected_downloaded_samples
		count_dCS = 0	#detected_communicating_samples
		count_dRS = 0	#detected_referrer_samples

		# Call virustotal Public API
		url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
		parameters = {"ip": IP, "apikey": publicAPIKey}
		response = urllib.urlopen("%s?%s" % (url, urllib.urlencode(parameters))).read()

		if response == "" :	#Hit the limit request rate of 600/min or 50K/day
			#return IP + "\tHitLimit"
			resultQueue.put(IP + "\tHitLimit")
			
		else :
			response_dict = json.loads(response)

			#if( response_dict["response_code"])
			# response_code == 1	:	item was indeed present and it could be retrieved
			# response_code == 0	:	No information regarding the IP address
			# response_code == -1	:	Submitted IP address is invalid
			# response_code == -2	:	requested item is still queued for analysis
			queryResult["RC"] = response_dict["response_code"]
			if response_dict["response_code"] == 1 : # Normal case 
				if "detected_urls" in response_dict :
					dUrls = response_dict["detected_urls"]
					count_dUrls = len(dUrls)
					queryResult["dUrls"] = count_dUrls

				if "detected_downloaded_samples" in response_dict :
					dDS = response_dict["detected_downloaded_samples"]
					count_dDS = len(dDS)
					queryResult["dDS"] = count_dDS

				if "detected_communicating_samples" in response_dict :
					dCS = response_dict["detected_communicating_samples"]
					count_dCS = len(dCS)
					queryResult["dCS"] = count_dCS

				if "detected_referrer_samples" in response_dict :
					dRs = response_dict["detected_referrer_samples"]
					count_dRS = len(dRS)
					queryResult["dRS"] = count_dRS

				if count_dUrls!=0 or count_dDS!=0 or count_dCS!=0 or count_dRS!=0 :
					reputation = "Malicious IP"
				else :
					reputation = "Legitimate IP"
			elif response_dict["response_code"] == 0 : 
				reputation = "Unknown IP"
			elif response_dict["response_code"] == -1 : 
				reputation = "Unknown IP"
			elif response_dict["response_code"] == -2 : 
				reputation = "Unknown IP"

			#return IP + "\t" + reputation + "\t" + str(queryResult)
			resultQueue.put(IP + "\t" + reputation + "\t" + str(queryResult))

"""
Parsing command line arguments
$ ./demo.py input.txt output.txt
sys.argv[0]=./demo.py
sys.argv[1]=input.txt
sys.argv[2]=output.txt
"""
start_time = time.time() # Record start time

publicAPIKey = "e42cb9f793be5db8afd714aa163aba164b06cd42533c61e489d134cc13529616"
if len(sys.argv) == 3 :
	# check the output file exist or not
	if os.path.isfile(sys.argv[2]): # File exist 
		print ("Alread have the output file in the directory")
	if os.path.isfile(sys.argv[2]+"_unCheckIPs"): # File exist 
		print ("Alread have the output_unCheckIPs file in the directory")
	else: #File not exist
		IPList = []
		with open(sys.argv[1]) as fr:
			for tmp in fr.readlines():
				IPList.append(tmp.rstrip("\n")) # Remove \n
		#fw = open(sys.argv[2],"w")
		
		countUnknownIP = 0
		countLegitimateIP = 0
		countMaliciousIP = 0
		
		PrivateIPList = []
		UnCheckIPList = []
		# Split the Long IPList into 550 IPs per list
		# if list = [1, 2 ,3 ,4 ,5 ,6 ,7 ] , size =3
		# it will split into [[1, 2, 3], [4, 5, 6], [7]]
		size = 550
		
		''' type of IP counter '''
		srcNum = 0 # number of src IP
		malNum = 0 # number of malicious
		unkNum = 0 # number of unknown
		''' sets stored already checked IP '''
		malIPSet = set()
		unkIPSet = set()
		legIPSet = set()
		''' number of query '''
		queryNum = 0
		
		''' read from file (already checked IP) '''
		# read mal IP set
		fmal_r = open( 'malIPSet', 'r' )
		for line in fmal_r.readlines() :
			malIPSet.add( line.rstrip('\n') )
		fmal_r.close()
		
		# read unk IP set
		funk_r = open( 'unkIPSet', 'r' )
		for line in funk_r.readlines() :
			unkIPSet.add( line.rstrip('\n') )
		funk_r.close()
		
		# read leg IP set
		fleg_r = open( 'legIPSet', 'r' )
		for line in fleg_r.readlines() :
			legIPSet.add( line.rstrip('\n') )
		fleg_r.close()
		
		
		splitIPList = [IPList[i:i+size] for i  in range(0, len(IPList), size)] # <type 'list'>
		for subIPList in splitIPList : # Go thought each subIPList with 550 IP
			
			# Multiprocess
			mulProcess = []
			resultQueue = multiprocessing.Queue()
			resultList = []
			
			for ip in subIPList:
				# src ip
				if ip.startswith('=') :
					# first src IP
					if srcNum == 0 :
						print ( "srcNum = " + str(srcNum) )
						srcNum += 1
						
						''' write in the file '''
						fw = open(sys.argv[2],"a")
						fw.write( ip + "\t" )
						fw.close()
						
					# second src IP ~
					else :
						print ( "srcNum = " + str(srcNum) )
						srcNum += 1
						
						''' analyze the results of this src IP '''
						resultQueue.put('STOP')
						resultList = dumpQueue(resultQueue)
						
						# Analyze result list
						for result in resultList:
							#IP	Unknown IP
							#IP	Legitimate IP
							#IP	Malicious IP
							#IP	Private IP
							#IP	HitLimit
							tmpList = result.split("\t")
							if tmpList[1] == "HitLimit":
								UnCheckIPList.append(tmpList[0])
							
							elif tmpList[1] == "Malicious IP":
								countMaliciousIP += 1
								malIPSet.add( tmpList[0] ) # add IP in set
								#print( tmpList[0] + "\t mal \n" )
								fmal_w = open( 'malIPSet', 'a' ) # write new checked mal IP
								fmal_w.write( tmpList[0] + '\n' )
								fmal_w.close()
							
							elif tmpList[1] == "Unknown IP":
								countUnknownIP += 1
								unkIPSet.add( tmpList[0] ) # add IP in set
								#print( tmpList[0] + "\t unk \n" )
								funk_w = open( 'unkIPSet', 'a' ) # write new checked unk IP
								funk_w.write( tmpList[0] + '\n' )
								funk_w.close()
								
							elif tmpList[1] == "Legitimate IP":
								countLegitimateIP += 1
								legIPSet.add( tmpList[0] ) # add IP in set
								#print( tmpList[0] + "\t leg \n" )
								fleg_w = open( 'legIPSet', 'a' ) # write new checked leg IP
								fleg_w.write( tmpList[0] + '\n' )
								fleg_w.close()
								
							else :
								PrivateIPList.append(tmpList[0])
						
						''' calculate the ratio of malicious '''
						total = float(countUnknownIP + countLegitimateIP + countMaliciousIP)
						ratio = countMaliciousIP / total
						#print ( ratio )
						''' write in the file '''
						fw = open(sys.argv[2],"a")
						# 5% malicious
						if ratio > 0.05 :
							fw.write( "Malicious IP \t" )
							fw.write( str(countMaliciousIP) + " / " + str(total) + "\t" )
							fw.write( "%.2f" % (ratio*100) + "\n" )
							malNum += 1
						else :
							fw.write( "Unknown IP \t" )
							fw.write( str(countMaliciousIP) + " / " + str(total) + "\t" )
							fw.write( "%.2f" % (ratio*100) + "\n" )
							unkNum += 1
						
						''' write src IP in the file '''
						fw.write( ip + "\t" )
						fw.close()
						
						''' clear the resultQueue '''
						while resultQueue.empty() == False :
							resultQueue.get()
						
						''' reset the counter '''
						countMaliciousIP = 0
						countUnknownIP = 0
						countLegitimateIP = 0
						
				# des IP
				else :
					print ( ip )
					
					if ip in malIPSet :
						countMaliciousIP += 1
						#print ( "mal Set" )
					elif ip in unkIPSet :
						countUnknownIP += 1
						#print ( "unk Set" )
					elif ip in legIPSet :
						countLegitimateIP += 1
						#print ( "leg Set" )
					else :
						process = multiprocessing.Process(target=checkIP,args=(ip, publicAPIKey, resultQueue))
						process.start()	# Run processes
						mulProcess.append(process)
						
						for process in mulProcess :
							process.join()
						
						''' number of query '''
						queryNum += 1
						print ( "queryNum = " + str(queryNum) )
						
			# After checking 550 IPs sleeping 1 min
			#time.sleep(60)# Sleep 60 second
		
		
		# If there are UnCheck IPs because of hit request limit -> write UnCheck IPs into file
		if len(UnCheckIPList)!=0 :
			fw2 = open(sys.argv[2]+"_unCheckIPs",'w')
			for ip in UnCheckIPList:
				fw2.write( ip + "\n")
			fw2.close()
		
		''' write in the file '''
		fw = open(sys.argv[2],"a")
		fw.write("\n--------\n") # python will convert \n to os.linesep
		fw.write("Total src IP : "+str(srcNum-1)+"\n") # python will convert \n to os.linesep
		fw.write("Malicious IP : "+str(malNum)+"\n") # python will convert \n to os.linesep
		fw.write("Unknown IP : "+str(unkNum)+"\n") # python will convert \n to os.linesep
		#fw.write("Legitimate IP : "+str(countLegitimateIP)+"\n") # python will convert \n to os.linesep
		fw.write("--------\n") # python will convert \n to os.linesep
		fw.write("UnCheck IP : " + str(UnCheckIPList)+"\n") # python will convert \n to os.linesep
		fw.write("Private IP : " + str(PrivateIPList)+"\n") # python will convert \n to os.linesep
		fw.close()

	print("Total Execution Time : %s (s)" % (time.time() - start_time))

else:
	print ("Usage: ./publicAPI_checkIPList.py input output")
	print ("Input format :\t218.65.30.61")
	print ("\t\t173.194.72.101")
	print ("\t\t140.116.164.72")
	print ("\t\t140.116.164.73")
