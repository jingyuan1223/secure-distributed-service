import requests
import json
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import sys
from binascii import b2a_hex, a2b_hex
import base64

USERNAME = 'randomusername' 
server_name = 'secure-shared-store'
session="ses"
userid="uid"

def post_request(server_name, action, body, node_certificate, node_key):
	'''
		node_certificate is the name of the certificate file of the client node (present inside certs).
		node_key is the name of the private key of the client node (present inside certs).
		body parameter is in the json format.
	'''
	request_url= 'https://{}/{}'.format(server_name,action)
	request_headers = {
		'Content-Type': "application/json"
		}
	response = requests.post(
		url= request_url,
		data=json.dumps(body),
		headers = request_headers,
		cert = (node_certificate, node_key),
	)
	with open(USERNAME, 'w') as f:
		f.write(response.content)
	return response

def login():
	'''
		Accept the
		 - user-id
		 - name of private key file(should be
		present in the userkeys folder) of the user.
		Generate the login statement and its signature.
		Send request to server with required parameters (action = 'login') using
		post_request function.
		The request body contains the user-id, statement and signed statement.
	'''
	# read in and set data
	uid=raw_input('Please input your use ID : ')
	global userid
	userid=uid
	uskname=raw_input('Please input your private key file name present inside userkeys folder : ')
	state="Client1 as "+uid+" logs into the Server"
	uskpath='userkeys/'+uskname
	sk=RSA.importKey(open(uskpath).read())
	signer=PKCS1_v1_5.new(sk)
	digest=SHA256.new(state.encode("utf8"))
	sign=signer.sign(digest)
	signa=base64.b64encode(sign)
	request_body={
        "user-id":uid,
        "statement":state,
        "signature":signa
    }

	# send request
	response = post_request(server_name,'login',request_body,'certs/client1.crt','certs/client1.key')
	respjson=response.content
	responsed=json.loads(respjson)
	status=responsed['status']
	if status == 200:
		global session
		sstok=responsed['session_token']
		print(uid+" login success")
		session=sstok
	else:
		print(uid+" login fail")
	return status

def checkin():
	'''
		Accept the
		 - DID
		 - security flag (1 for confidentiality  and 2 for integrity)
		Send the request to server with required parameters (action = 'checkin') using post_request().
		The request body contains the required parameters to ensure the file is sent to the server.
	'''
	# read in
	did=raw_input('Please input the DID : ')
	flag=raw_input('Please input the Security Flag : ')

	# get checkin file content
	filepath='documents/checkin/'+did
	f=open(filepath)
	filecontent=f.read()

	# send request to server
	global session
	global userid
	body={
		'UID':userid,
		'Session':session,
		'DID':did,
		'SecurityFlag':flag,
		'FileContent':filecontent
	}
	response=post_request(server_name,'checkin',body,'certs/client1.crt','certs/client1.key')
	respjson=response.content	
	responsed=json.loads(respjson)

	# get response and react
	status=responsed['status']
	if status==200:
		print(did+" checkin success")
	elif status==702:
		print("Checkin access denied")
	else:
		print("Checkin Fail")
	return

def checkout():
	'''
		Accept the DID.
		Send request to server with required parameters (action = 'checkout') using post_request()
	'''
	# read in DID
	did=raw_input('Please input the DID : ')

	# send request to server
	global session
	global userid
	body={
		'UID':userid,
		'DID':did,
		'Session':session
	}
	respjson = post_request(server_name, 'checkout', body, 'certs/client1.crt', 'certs/client1.key')
	response=json.loads(respjson.content)

	# get status
	status=response['status']

	# get file content from response and write the file into checkout directory
	if status==200:
		print(did+" checkout success")
		filecontent = response['FileContent']
		filepath = 'documents/checkout/' + did
		with open(filepath, 'w+') as f:
			f.write(filecontent)
	elif status==702:
		print("Checkout Access denied")
	elif status==704:
		print(did+" not found")
	elif status==703:
		print("Broken integrity")
	else:
		print("Checkout Fail")
	return

def grant():
	'''
		Accept the
		 - DID
		 - target user to whom access should be granted (0 for all user)
		 - type of acess to be granted (1 - checkin, 2 - checkout, 3 - both checkin and checkout)
		 - time duration (in seconds) for which acess is granted
		Send request to server with required parameters (action = 'grant') using post_request()
	'''
	did=raw_input('Please input the DID : ')
	tuid=raw_input('Please input the TargetUser : ')
	accr=raw_input('Please input the AccessRight : ')
	tim=raw_input('Please input the time : ')
	global session
	global userid
	body={
		'UID':userid,
		'Session':session,
		'DID':did,
		'TUID':tuid,
		'AccessRight':accr,
		'Time':tim
	}
	respjson = post_request(server_name, 'grant', body, 'certs/client1.crt', 'certs/client1.key')
	response = json.loads(respjson.content)
	status=response['status']
	if status==200:
		print('Grant success')
	elif status==702:
		print('Access denied')
	else:
		print('Grant fail')
	return

def delete():
	'''
		Accept the DID to be deleted.
		Send request to server with required parameters (action = 'delete')
		using post_request().
	'''
	did=raw_input('Please input the DID : ')
	global session
	global userid
	body = {
		'UID': userid,
		'Session': session,
		'DID': did
	}
	respjson = post_request(server_name, 'delete', body, 'certs/client1.crt', 'certs/client1.key')
	response = json.loads(respjson.content)
	status = response['status']
	if status==200:
		print(did+' delete success')
	elif status==702:
		print('Access Denied')
	elif status==704:
		print(did+' not found')
	else:
		print('Delete fail')
	return

def logout():
	'''
		Ensure all the modified checked out documents are checked back in.
		Send request to server with required parameters (action = 'logout') using post_request()
		The request body contains the user-id, session-token
	'''
	global session
	global userid
	body = {
		'UID': userid,
		'Session': session
	}
	respjson = post_request(server_name, 'logout', body, 'certs/client1.crt', 'certs/client1.key')
	response = json.loads(respjson.content)
	status=response['status']
	if status==200:
		print(userid+' logout success')
	else:
		print('logout fail')
	exit() #exit the program

def main():
	'''
		Authenticate the user by calling login.
		If the login is successful, provide the following options to the user
			1. Checkin
			2. Checkout
			3. Grant
			4. Delete
			5. Logout
		The options will be the indexes as shown above. 
	'''
	loginstatus=login()
	if loginstatus==200:
		op=raw_input('Please input options : ')
		while op!='5':
			if op=='1':
				checkin()
			if op=='2':
				checkout()
			if op=='3':
				grant()
			if op=='4':
				delete()
			op=raw_input('Please input options : ')
		logout()


if __name__ == '__main__':
	main()
