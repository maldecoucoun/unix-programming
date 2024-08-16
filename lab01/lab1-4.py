from pwn import *

def retrieve_ip():
    url = "http://ipinfo.io/ip"
    r = remote("ipinfo.io", 80)  
    
    r.send("GET /ip HTTP/1.1\r\n")
    r.send("Host: ipinfo.io\r\n")
    r.send("Connection: close\r\n\r\n")

    response = r.recvall()
    r.close()
    ip_address = response.strip().decode("utf-8")
    return ip_address

if __name__ == "__main__":
    ip_address = retrieve_ip()
    print(ip_address)
