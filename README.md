# CS372_Project04
# Brandon Nelson

## checksum.py
   the program will read in data from a path file, convert any text to bytes, compute the length of the header and payload for a checksum value, and evaluate the computed checksum with the original stored tcp header checksum. If these checksum values are equal, a PASS will be printed, if they are not then a FAIL.


## tcp_data
    folder containing 10 tcp_addrs_n.txt and 10 tcp_data_n.dat files. tcp_addrs_n.txt contain the source and destination IPs to simulate communication between two machines. tcp_data_n.dat contains the payload data and header that can be read to obtain a new checksum.

