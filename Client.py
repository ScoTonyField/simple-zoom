'''
@author: Zhi Ye (z5314977)
@version: python3
'''
import socket
import sys
import time
import threading
import os

class Client:
    def __init__(self, host, tcp_port, udp_port):
        self.host = host
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_port = udp_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, tcp_port))
        self.active_user = {}
        self.login = False
        # create basic response
        self.response_dict = {
            '0': 'Welcome to TOOM!',
            '1': 'Invalid Password. Please try again',
            '2': 'Invalid Password. Your account has been blocked. Please try again later',
            '3': 'Enter one of the following commands (MSG, DLT, EDT, RDM, ATU, OUT, UDP):'
        }
        # Login operation
        while not self.login:
            username = input('Username: ')
            password = input('Password: ')
            self.sock.send('{},{},{}'.format(username, password, self.udp_port).encode())
            message = self.sock.recv(1024)
            if message.decode() == '0':
                self.login = True
                self.username = username
                print(self.response_dict['0'])
            elif message.decode() == '1':
                print(self.response_dict['1'])
            else:
                print(self.response_dict['2'])
                os._exit(0)
        # activate thread to accecpt udp connection
        thread = threading.Thread(target=self.udpListen)
        thread.start()
        # Commands operation
        while self.login:
            print(self.response_dict['3'])
            cmd = input()
            if 'UDP' not in cmd and 'ATU' != cmd:
                # proceed command expect UDP and ATU
                self.sock.send(cmd.encode())
                sendBackMsg = self.sock.recv(1024)
                print(sendBackMsg.decode())
                if (sendBackMsg.decode() == 'Bye! {}'.format(self.username)):
                    os._exit(0)
            elif 'ATU' == cmd:
                self.sock.send(cmd.encode())
                sendBackMsg = self.sock.recv(1024)
                print(sendBackMsg.decode())
                if sendBackMsg.decode() != 'No other active users':
                    atuList = sendBackMsg.decode().split('\n')
                    for atu in atuList:
                        if atu:
                            self.active_user[atu.split(', ')[0]] = [
                                atu.split(', ')[1],  # address of user
                                atu.split(', ')[2]   # udp port of user
                            ]
            else:
                self.udpSend(cmd)


    def udpSend(self, cmd):
        cmdList = cmd.split(' ')
        if len(cmdList) != 3:
            # check command format is valid
            print('Invalid command input of UDP, please follow the format of example: UDP tony example1.mp4.')
        else:
            targetUser = cmdList[1]
            filename = cmdList[2]
            if not os.path.exists(filename):
                # check file exists
                print('File does not exist, please check.')
            elif targetUser not in self.active_user:
                # check target user is active
                print('Target user is not active, send when active.')
            else:
                address = self.active_user[targetUser][0]
                port = int(self.active_user[targetUser][1])
                # send basic identification data to the target user
                self.udp.sendto('{} {}'.format(self.username, filename).encode(), (address, port))
                print('---Uploading data, please wait---')
                # read file and send to the target user
                with open(filename, 'rb') as file:
                    while True:
                        data = file.read(2048)
                        if str(data) == "b''":
                            # check if data is the end of file and send end signal to target user
                            self.udp.sendto(data, (address, port))
                            break
                        else:
                            # send binary data to target user
                            self.udp.sendto(data, (address, port))
                            # delay for a while incase of warning
                            time.sleep(0.01)
                print('{} has been uploaded'.format(filename))

    def udpListen(self):
        cnt = 0
        self.udp.bind((self.host, self.udp_port))
        while True:
            message, _ = self.udp.recvfrom(2048)
            if cnt == 0:
                # accept present username and file name at the begining
                presentUser = message.decode().split(' ')[0]
                filename = presentUser + '_' + message.decode().split(' ')[1]
                cnt += 1    # move to next step to accecpt file data or comfirm receiving file data
                file = open(filename, 'wb')
            elif str(message) == "b''":
                file.close()
                print('Received {} from {}'.format(
                    filename.split('_')[1],
                    presentUser
                ))
                print(self.response_dict['3'])
                cnt = 0     # reset to accecpt other file
            else:
                file.write(message)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('Lack of parameters, example: python3 Server.py host_num port_num.')
    else:
        c = Client(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))