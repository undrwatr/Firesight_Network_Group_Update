        
#
# Generated FMC REST API sample script
#
 
import json
import sys
import requests
import cred


# pull in list of stores from file
stores = open("stores.txt", "r")

#use that list of stores to generate a script to pull the data from the database

#use the data from the database to generate the list of literals down below for upload

#This is the part of the code from the API EXPLORER that has been imported 
server = cred.server
 
username = cred.username
if len(sys.argv) > 1:
    username = sys.argv[1]
password = cred.password
if len(sys.argv) > 2:
    password = sys.argv[2]
               
r = None
headers = {'Content-Type': 'application/json'}
api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
auth_url = server + api_auth_path
try:
    # 2 ways of making a REST call are provided:
    # One with "SSL verification turned off" and the other with "SSL verification turned on".
    # The one with "SSL verification turned off" is commented out. If you like to use that then 
    # uncomment the line where verify=False and comment the line with =verify='/path/to/ssl_certificate'
    # REST call with SSL verification turned off: 
    r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
    # REST call with SSL verification turned on: Download SSL certificates from your FMC first and provide its path for verification.
    # r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify='/path/to/ssl_certificate')
    auth_headers = r.headers
    auth_token = auth_headers.get('X-auth-access-token', default=None)
    if auth_token == None:
        print("auth_token not found. Exiting...")
        sys.exit()
except Exception as err:
    print ("Error in generating auth token --> "+str(err))
    sys.exit()
 
headers['X-auth-access-token']=auth_token
 
api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups/005056A2-7618-0ed3-0000-515396143619"    # param
url = server + api_path
if (url[-1] == '/'):
    url = url[:-1]
 
# PUT OPERATION
 

 

 
# The literals data is generated from the sql query and then generates this to be uploaded
put_data = {
  "id": "005056A2-7618-0ed3-0000-515396143619",
  "name": "BOPIS_TEST",
  "type": "NetworkGroup",
  "objects": [
 ],
  "literals": [
 #data to be built from above
  ]
}
try:
    # REST call with SSL verification turned off:
    r = requests.put(url, data=json.dumps(put_data), headers=headers, verify=False)
    # REST call with SSL verification turned on:
    # r = requests.put(url, data=json.dumps(put_data), headers=headers, verify='/path/to/ssl_certificate')
    status_code = r.status_code
    resp = r.text
    if (status_code == 200):
        print("Put was successful...")
        json_resp = json.loads(resp)
        print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
    else:
        r.raise_for_status()
        print("Status code:-->"+status_code)
        print("Error occurred in PUT --> "+resp)
except requests.exceptions.HTTPError as err:
    print ("Error in connection --> "+str(err))
finally:
    if r: r.close()
