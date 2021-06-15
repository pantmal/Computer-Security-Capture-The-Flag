from datetime import date
from dateutil.rrule import rrule, DAILY
import hashlib
import os

a = date(2021, 1, 1)
b = date(2021, 2, 28)

#Uncomment the following lines to execute the brute force attempts.

# for dt in rrule(DAILY, dtstart=a, until=b):
#     # print()
#     string=dt.strftime("%Y-%m-%d") + " bigtent" 
#     encoded=string.encode()
#     result = hashlib.sha256(encoded)
#     print(string)
#     # print(result.hexdigest())
#     file = open("passphrase.key", "w")
#     file.write(result.hexdigest())
#     file.close()
#     os.system('gpg --passphrase-file passphrase.key --batch --decrypt firefox.log.gz.gpg')


string="2021-01-04 bigtent" 
encoded=string.encode()
result = hashlib.sha256(encoded)
print(string)
print(result.hexdigest())
file = open("passphrase.key", "w")
file.write(result.hexdigest())
file.close()
os.system('gpg --passphrase-file passphrase.key --batch --decrypt signal.log.gpg > signal.log')
