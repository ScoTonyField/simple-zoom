import socket
import sys
import time

class Server:
    def __init__(self, host, port, failed_num):
        # TODO: change when mutiple user concerned - username, password, login
        self.login = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen()
        self.username = ''
        self.password = ''
        self.udp_port = 0
        self.login_log = {}
        self.failed_num = failed_num
        self.block = {}
        print('Server established...')
        while True:
            self.client, self.address = self.sock.accept()
            print('Connection with {} successfully'.format(self.address))
            self.tcpConnect()
            self.login = False

    def tcpConnect(self):
        cnt = 0
        while not self.login:
            message = self.client.recv(1024)
            self.username = message.decode().split(',')[0]
            self.password = message.decode().split(',')[1]
            self.udp_port = message.decode().split(',')[2]
            if self.isBlock():
                # self.client.send('Your account is blocked due to multiple login failures. Please try again later')
                self.client.send('2'.encode())
                break

            if self.isValidLogin():
                print('{} Login'.format(self.username))
                self.client.send('0'.encode())  # 0 stands for login successfully
                self.login = True
                self.login_log[self.username] = time.strftime('%d %b %Y %H:%M:%S') + ',' + self.udp_port
                self.updateUserLog()
            elif cnt < self.failed_num:
                self.client.send('1'.encode())  # 1 stands for login unsuccessfully but has not been block
                cnt += 1
            else:
                self.client.send('2'.encode())  # 2 stands for this IP has been blocked for 10sec
                self.block[self.address[0]] = time.time()
                break

    def isBlock(self):
        current_time = time.time()
        if self.address[0] not in self.block:
            return False
        elif current_time - self.block[self.address[0]] < 10:
            return True
        else:
            del(self.block[self.address[0]])
            return False

    def isValidLogin(self):
        user_list = []
        with open('credentials.txt', 'r') as file:
            for line in file.readlines():
                # username, password = line.strip('\n').split(' ')
                new_line = line.strip('\n')
                username = new_line.split(' ')[0]
                password = new_line.split(' ')[1]
                user_list.append([username, password])
        for user in user_list:
            if self.username == user[0] and self.password == user[1]:
                return True
        return False

    def updateUserLog(self):
        with open('userlog.txt', 'w+') as logfile:
            for (idx, name) in enumerate(self.login_log):
                logline = '{}; {}; {}; {}; {}\n'.format(
                    idx,
                    self.login_log[name].split(',')[0],
                    name,
                    self.address[0], # TODO: change when mutiple user concerned
                    self.login_log[name].split(',')[1],
                )
                logfile.write(logline)



if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('Lack of parameters, example: python3 Server.py host_num port_num.')
    s = Server(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))