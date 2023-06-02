import socket
import sys
import threading
from multiprocessing import Process

ip=""
sport=""
dport=""

def P2PListen():
    global sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', sport))

    while True:
        data = sock.recv(1024)
        print('\rpeer: {}\n> '.format(data.decode()), end='')

def P2PSend():
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', dport))
    while True:
        msg = input('> ')
        sock.sendto(msg.encode(), (ip, dport))

def Command(datas):
    global ip, sport, dport
    if(datas[0]=="who"):
        who=input(datas[1])
        sock.sendto(b'messageTo '+who.encode(), server)
        return True
    elif(datas[0]=="emptyYet"):
        who=input(datas[1])
        sock.sendto(b'username '+username.encode(), server)
        return True
    elif(datas[0]=="infos"):
        
        ip, sport, dport = datas[1].split(' ')
        sport = int(sport)
        dport = int(dport)

        return False

    elif(datas[0]=="messageRequest"):
        
        ip, sport, dport = datas[1].split(' ')
        sport = int(sport)
        dport = int(dport)

        return False

    return True

def ServerListen():
    while True:
        data = sock.recv(1024)
        dataStr=data.decode("utf-8")
        datas=dataStr.split(" ",1)
        
        if(Command(datas)==False):
            break
        



server = ('127.0.0.1', 55555)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 50001))

username=input("What is your username:")
sock.sendto(b'username '+username.encode(), server)

ServerListen()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', sport))
sock.sendto(b'0', (ip, dport))

listener = threading.Thread(target=P2PListen, daemon=True);
listener.start()

P2PSend()





# print('\ngot peer')
# print('  ip:          {}'.format(ip))
# print('  source port: {}'.format(sport))
# print('  dest port:   {}\n'.format(dport))


# print('ready to exchange messages\n')


# # send messages
# # equiv: echo 'xxx' | nc -u -p 50002 x.x.x.x 50001
