from flask import Flask, request, jsonify
from flask_restful import Resource, Api
import json
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import random
import os
import time
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import base64
from Crypto.Cipher import PKCS1_OAEP

secure_shared_service = Flask(__name__)
api = Api(secure_shared_service)

class welcome(Resource):
	def get(self):
		return "Welcome to the secure shared server!"

class login(Resource):
	def post(self):
		'''
            Verify the signed statement.
            The same keys ('status', 'message', 'session_token') will be used.
        '''
		data = request.get_json()
		req=data
		uid=req['user-id']
		state=req['statement']
		sign=req['signature']
		upkpath='userpublickeys/'+uid+'.pub'
		pk=RSA.importKey(open(upkpath).read())
		verifier=PKCS1_v1_5.new(pk)
		digest2=SHA256.new(state.encode("utf8"))
		if verifier.verify(digest2,base64.b64decode(sign)):
			success=1
		else:
			success=0
		if success:
			session_token = uid+ str(random.randint(100,999)) 
			response = {
				"status": 200,
				"session_token": session_token
			}

			# add user and corresponding session into the metadata(database)
			sess_rcd_file = 'sesrcd.json'
			if os.path.exists(sess_rcd_file):
				sessrcd=json.load(open(sess_rcd_file,'r'))
				sessrcd[uid]=session_token
				json.dump(sessrcd,open(sess_rcd_file,'w+'))
			else:
				user_session = {uid: session_token}
				with open(sess_rcd_file, 'w+') as f:
					json.dump(user_session, f)
		else:
			response = {"status": 700}
		return jsonify(response)

class checkout(Resource):
	def post(self):
		'''
        Response status codes
        1) 200 - Document Successfully checked out
        2) 702 - Access denied to check out
        3) 703 - Check out failed due to broken integrity
        4) 704 - Check out failed since file not found on the server
        5) 700 - Other failures
        '''
		# get request content
		data = request.get_json()
		req=data
		uid = req['UID']
		sess = req['Session']
		did = req['DID']

		# check session
		rightsession = False
		rcd = json.load(open('sesrcd.json', 'r'))
		if uid in rcd:
			if rcd[uid] == sess:
				rightsession = True

		# check access right
		havefile=False
		rightaccess=False
		integrity=False
		filepath='documents/'+did
		metapath=filepath+'.json'
		if os.path.exists(filepath):
			havefile=True
			metad=json.load(open(metapath,'r'))
			if metad['Owner'] == uid:
				rightaccess = True
			else:
				if uid in metad:
					if metad[uid] == "2" or metad[uid] == "3":
						allowtime = metad[uid + 'st'] + metad[uid + 'lt']
						nowtime = time.time()
						if nowtime <= allowtime:
							rightaccess = True
				if '0' in metad:
					if metad['0']=="2" or metad['0']=="3":
						allowtime=metad['0'+'st']+metad['0'+'lt']
						nowtime=time.time()
						if nowtime<=allowtime:
							rightaccess=True

		# decrpyt and check integrity
		if rightaccess==True and rightsession==True and havefile==True:
			metad=json.load(open(metapath,'r'))
			flag=metad['Flag']
			if flag==2:
				pk=RSA.importKey(open('../certs/secure-shared-store.pub').read())
				verifier=PKCS1_v1_5.new(pk)
				fcontent=open(filepath).read()
				sign=metad['Signature']
				digest2=SHA256.new(fcontent.encode("utf8"))
				if verifier.verify(digest2,base64.b64decode(sign)):
					integrity=True
					plaintxt=fcontent
			else:
				integrity=True
				cikey=metad['EncryptedKey']
				sk=RSA.importKey(open('../certs/secure-shared-store.key').read())
				decryptor=PKCS1_OAEP.new(sk)
				aeskey=decryptor.decrypt(base64.b64decode(cikey))
				mod=metad['AESMODE']
				hexcitxt=open(filepath).read()
				citxt=a2b_hex(hexcitxt)
				cryptor=AES.new(aeskey.encode('utf-8'), mod, b'0000000000000000')
				plaintxt=cryptor.decrypt(citxt)
				plaintxt=plaintxt.decode('utf-8').rstrip('\0')

		# response
		if rightsession:
			if havefile:
				if rightaccess:
					if integrity:
						status=200
					else:
						status=703
				else:
					status=702
			else:
				status=704
		else:
			status=702
		if status==200:
			response={
				'status':status,
				'FileContent':plaintxt
			}
		else:
			response={'status':status}
		return jsonify(response)

class checkin(Resource):
	def post(self):
		'''
        Response status codes:
        1) 200 - Document Successfully checked in
        2) 702 - Access denied to check in
        3) 700 - Other failures
        '''
		# get request content : DID, Flag, Content
		data = request.get_json()
		req=data
		uid=req['UID']
		sess=req['Session']
		did = req['DID']
		flag = req['SecurityFlag']
		content = req['FileContent']

		# check session
		rightsession=False
		rcd=json.load(open('sesrcd.json','r'))
		if uid in rcd:
			if rcd[uid]==sess:
				rightsession=True

		# check access right
		rightaccess=False
		didpath='documents/'+did
		if os.path.exists(didpath):
			metaf='documents/'+did+'.json'
			metad=json.load(open(metaf,'r'))
			if metad['Owner']==uid:
				rightaccess=True
			else:
				if uid in metad:
					if metad[uid]=="1" or metad[uid]=="3":
						allowtime=metad[uid+'st']+metad[uid+'lt']
						nowtime=time.time()
						if nowtime<=allowtime:
							rightaccess=True
				if '0' in metad:
					if metad['0']=="1" or metad['0']=="3":
						allowtime=metad['0'+'st']+metad['0'+'lt']
						nowtime=time.time()
						if nowtime<=allowtime:
							rightaccess=True
		else:
			rightaccess=True
			ownermeta={'Owner':uid}
			metaf='documents/'+did+'.json'
			with open(metaf,'w+') as f:
				json.dump(ownermeta,f)

		# encrypt
		if rightaccess==True and rightsession==True:
			# security flag and then encrypt
			if flag == "1":
				# AES
				key = "keyskeyskeyskeys"
				mod = AES.MODE_OFB
				cryptor = AES.new(key.encode('utf-8'), mod, b'0000000000000000')
				length = 16
				cnt = len(content)
				if cnt % length != 0:
					add0 = length - (cnt % length)
				else:
					add0 = 0
				entxt = content + ('\0' * add0)
				citxt = cryptor.encrypt(entxt.encode('utf-8'))
				hexcitxt=b2a_hex(citxt)
				with open('documents/'+did,'w+') as f:
					f.write(hexcitxt)

				# update meta
				pk=RSA.importKey(open('../certs/secure-shared-store.pub').read())
				encryptor=PKCS1_OAEP.new(pk)
				cikey=base64.b64encode(encryptor.encrypt(key))
				meta=json.load(open('documents/'+did+'.json','r'))
				meta['Owner']=uid
				meta['Flag']=1
				meta['AESMODE']=mod
				meta['EncryptedKey']=cikey
				with open('documents/'+did+'.json','w+') as f:
					json.dump(meta,f)
			if flag == "2":
				# Use server sk to signature
				sk = RSA.importKey(open('../certs/secure-shared-store.key').read())
				signer=PKCS1_v1_5.new(sk)
				digest=SHA256.new(content.encode("utf8"))
				sign=signer.sign(digest)
				signature=base64.b64encode(sign)
				with open('documents/'+did,'w+') as f:
					f.write(content)

				# updata meta
				meta = json.load(open('documents/' + did + '.json','r'))
				meta['Owner']=uid
				meta['Flag']=2
				meta['Signature']=signature
				with open('documents/'+did+'.json','w+') as f:
					json.dump(meta,f)

		# response
		status=0
		if rightsession==True and rightaccess==True:
			if flag=="1" or flag=="2":
				status=200
			else:
				status=700
		else:
			status=702
		response = {
			'status': status
		}
		return jsonify(response)

class grant(Resource):
	def post(self):
		'''
			Response status codes:
			1) 200 - Successfully granted access
			2) 702 - Access denied to grant access
			3) 700 - Other failures
		'''
		# read in did, tuid, r, t
		data = request.get_json()
		req=data
		uid=req['UID']
		sess=req['Session']
		did=req['DID']
		tuid=req['TUID']
		accr=req['AccessRight']
		tim=req['Time']

		# check session
		rightsession = False
		rcd = json.load(open('sesrcd.json', 'r'))
		if uid in rcd:
			if rcd[uid] == sess:
				rightsession = True

		# check grant right
		rightgrant=False
		didpath='documents/'+did
		metapath=didpath+'.json'
		if os.path.exists(didpath):
			metad=json.load(open(metapath,'r'))
			if metad['Owner']==uid:
				rightgrant=True
				metad[tuid]=accr
				metad[tuid+'st']=time.time()
				metad[tuid+'lt']=int(tim)
				json.dump(metad,open(metapath,'w+'))
				status=200
			else:
				status=702
		else:
			status=700
		if rightsession==False:
			status=702
		response={'status':status}
		return jsonify(response)

class delete(Resource):
	def post(self):
		'''
			Response status codes:
			1) 200 - Successfully deleted the file
			2) 702 - Access denied to delete file
			3) 704 - Delete failed since file not found on the server
			4) 700 - Other failures
		'''
		data = request.get_json()
		req=data
		uid=req['UID']
		sess=req['Session']
		did=req['DID']

		# check session
		rightsession = False
		rcd = json.load(open('sesrcd.json', 'r'))
		if uid in rcd:
			if rcd[uid] == sess:
				rightsession = True

		# check access right and file existence
		rightaccess = False
		haveFile=False
		didpath = 'documents/' + did
		metapath = didpath + '.json'
		if os.path.exists(didpath):
			haveFile=True
			metad=json.load(open(metapath,'r'))
			if metad['Owner']==uid:
				rightaccess=True
				os.remove(didpath)
				os.remove(metapath)
		if rightsession:
			if haveFile:
				if rightaccess:
					status=200
				else:
					status=702
			else:
				status=704
		else:
			status=702
		response={'status':status}
		return jsonify(response)

class logout(Resource):
	def post(self):
		'''
			Response status codes:
			1) 200 - Successfully logged out
			2) 700 - Failed to log out
		'''
		data = request.get_json()
		uid=data['UID']
		sess=data['Session']
		# check session
		rightsession = False
		rcd = json.load(open('sesrcd.json', 'r'))
		if uid in rcd:
			if rcd[uid] == sess:
				rightsession = True
				rcd.pop(uid)
				json.dump(rcd, open('sesrcd.json', 'w+'))
		if rightsession:
			status=200
		else:
			status=700
		response={'status':status}
		return jsonify(response)

api.add_resource(welcome, '/')
api.add_resource(login, '/login')
api.add_resource(checkin, '/checkin')
api.add_resource(checkout, '/checkout')
api.add_resource(grant, '/grant')
api.add_resource(delete, '/delete')
api.add_resource(logout, '/logout')

def main():
	secure_shared_service.run(debug=True)

if __name__ == '__main__':
	main()
