import socket
import sys
import time

class Client:
    def __init__(self, host='localhost', port=8888, udp_port=4000):
        print('Try connecting...')
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_port = udp_port
        print(self.udp.getsockname())
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        print('Connect to server successfully.')
        self.login = False
        self.status = True
        response_dict = {
            '0': 'Welcome to TOOM!',
            '1': 'Invalid Password. Please try again',
            '2': 'Invalid Password. Your account has been blocked. Please try again later',
            '3': 'Enter one of the following commands (MSG, DLT, EDT, RDM, ATU, OUT):'
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
                print(response_dict['0'])
            elif message.decode() == '1':
                print(response_dict['1'])
            else:
                print(response_dict['2'])
                break
        # Commands operation
        while self.login:
            print(response_dict['3'])
            cmd = input()
            self.sock.send(cmd.encode())
            sendBackMsg = self.sock.recv(1024)
            print(sendBackMsg.decode())

    def logOut(self):
        if self.login:
            self.sock.send('logout'.encode())
            print('Bye! {}'.format(self.username))
            self.login = False
            self.status = False

if __name__ == '__main__':
    c = Client()