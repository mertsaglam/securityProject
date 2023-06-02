import socket


def Command(datas,address):
    if(datas[0]=="username"):
        users[datas[1]]=address
        print(users)
        print('connection from: {}'.format(address))
        if(len(users)<=1):
            response="emptyYet There is no one here yet. \nClick enter to try again."
        else:
            response="who Who do you want to talk to? "
            for i in users.keys():
                if(i!=datas[1]):
                    response+=i+", "

        sock.sendto(response.encode(), address)
        clients.append(address)
        
    elif(datas[0]=="messageTo"):
        print(datas[1])
        if(datas[1] not in users.keys()):
            response="wrongUsername Wrong username. \nwho Who do you want to talk to? "
            for i in users.keys():
                if(i!=datas[1]):
                    response+=i+", "
        else:
            addr, port = address
            response="messageRequest {} {} {}".format(addr, port, known_port)
            sock.sendto(response.encode(), users[datas[1]])

            addr, port = users[datas[1]]
            response="infos {} {} {}".format(addr, port, known_port)
            

        sock.sendto(response.encode(), address)
    

known_port = 50002

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 55555))
users={}
while True:
    clients = []

    while True:
        data, address = sock.recvfrom(128)
        dataStr=data.decode("utf-8")
        datas=dataStr.split(" ",1)
        Command(datas,address)



