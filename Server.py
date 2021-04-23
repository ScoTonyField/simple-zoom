import socket
import sys
import time
import threading
import re


class Server:
    def __init__(self, host, port, failed_num):
        # TODO: change when mutiple user concerned - username, password, login
        self.login = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen()
        self.login_log = {}
        self.msg_log = {}
        self.block = {}
        print('Server established...')
        while True:
            client, address = self.sock.accept()
            print('Connection with {} successfully'.format(address))
            thread = threading.Thread(target=self.tcpConnect, args=(client, address, failed_num))
            thread.start()
            # self.login = False

    def tcpConnect(self, client, address, failed_num):
        self.updateUserLog()
        login = False
        cnt = 0
        while not login:
            message = client.recv(1024)
            username = message.decode().split(',')[0]
            password = message.decode().split(',')[1]
            udp_port = message.decode().split(',')[2]
            if self.isBlock(address):
                # self.client.send('Your account is blocked due to multiple login failures. Please try again later')
                client.send('2'.encode())
                break

            if self.isValidLogin(username, password):
                print('{} Login'.format(username))
                client.send('0'.encode())  # 0 stands for login successfully
                login = True
                self.login_log[username] = time.strftime('%d %b %Y %H:%M:%S') + ',' + udp_port
                self.updateUserLog(address)
            elif cnt < failed_num:
                print(username)
                client.send('1'.encode())  # 1 stands for login unsuccessfully but has not been block
                cnt += 1
            else:
                client.send('2'.encode())  # 2 stands for this IP has been blocked for 10sec
                self.block[address[0]] = time.time()
                break
        while login:
            afterLoginMsg = client.recv(1024)
            if afterLoginMsg.decode() == 'logout':
                login = False
                client.close()
            elif 'MSG ' in afterLoginMsg.decode():
                # TODO: empty message and validation
                # print(afterLoginMsg.decode()[4:])
                msg = afterLoginMsg.decode()[4:]
                postTime = time.strftime('%d %b %Y %H:%M:%S')
                msgId = postTime + '|' + username
                self.msg_log[msgId] = [msg, 0]
                self.updateMsgLog()
                msgIndex = list(self.msg_log).index(msgId) + 1
                client.send('Message #{} posted at {}.'.format(msgIndex, postTime).encode())
                print('{} posted MSG #{} "{}" at {}'.format(username, msgIndex, msg, postTime))
            elif 'DLT ' in afterLoginMsg.decode():
                pattern = re.compile(r'#\d+')
                valid, validMsg = self.isDLTValid(afterLoginMsg.decode(), username)
                if valid:
                    msgIndex = pattern.findall(afterLoginMsg.decode())[0]
                    givenTime = afterLoginMsg.decode()[afterLoginMsg.decode().index(msgIndex) + len(msgIndex) + 1:]
                    givenId = givenTime + '|' + username
                    deleteMsg = self.msg_log[givenId][0]
                    self.msg_log.pop(givenId)
                    self.updateMsgLog()
                    deleteTime = time.strftime('%d %b %Y %H:%M:%S')
                    client.send('Message {} deleted at {}'.format(
                        msgIndex,
                        deleteTime
                    ).encode())
                    print('{} deleted MSG {} "{}" at {}.'.format(
                        username,
                        msgIndex,
                        deleteMsg,
                        deleteTime
                    ))
                else:
                    client.send(validMsg.encode())
            else:
                client.sent('Error. Invalid command!'.encode())

    def isDLTValid(self, message, username):
        pattern = re.compile(r'#\d+')
        if not pattern.findall(message):
            return [False, 'Wrong message number, please checked']
        msgNum = int(pattern.findall(message)[0].split('#')[1])
        if msgNum > len(self.msg_log):
            return [False, 'Wrong message number, please checked']
        else:
            givenTime = message[message.index(pattern.findall(message)[0]) + len(pattern.findall(message)[0]) + 1:]
            givenId = givenTime + '|' + username
            # TODO: givenTime validation
            if givenId not in self.msg_log:
                return [False, 'Wrong timestamp or these message not belong to you']
            else:
                return [True, '']



    def isUserMsg(self, number, username):
        with open('messagelog.txt', 'r') as file:
            for line in file.readlines():
                lineNum = line.split(';')[0]
                name = line.split(';')[2].split(' ')[1]
                if number == lineNum and username == name:
                    return True
            return False


    def updateMsgLog(self):
        with open('messagelog.txt', 'w+') as file:
            for (idx, msgId) in enumerate(self.msg_log):
                logline = '{}; {}; {}; {}; {}\n'.format(
                    idx + 1,
                    msgId.split('|')[0],
                    msgId.split('|')[1],
                    self.msg_log[msgId][0],
                    'yes' if self.msg_log[msgId][1] else 'no'
                )
                file.write(logline)

    def isBlock(self, address):
        current_time = time.time()
        if address[0] not in self.block:
            return False
        elif current_time - self.block[address[0]] < 10:
            return True
        else:
            del(self.block[address[0]])
            return False

    def isValidLogin(self, username, password):
        user_list = []
        with open('credentials.txt', 'r') as file:
            for line in file.readlines():
                # username, password = line.strip('\n').split(' ')
                new_line = line.strip('\n')
                defaultUsername = new_line.split(' ')[0]
                defaultPassword = new_line.split(' ')[1]
                user_list.append([defaultUsername, defaultPassword])
        for user in user_list:
            if username == user[0] and password == user[1]:
                return True
        return False

    def updateUserLog(self, *address):
        if (address):
            with open('userlog.txt', 'w+') as logfile:
                for (idx, name) in enumerate(self.login_log):
                    logline = '{}; {}; {}; {}; {}\n'.format(
                        idx + 1,
                        self.login_log[name].split(',')[0],
                        name,
                        address[0],
                        self.login_log[name].split(',')[1],
                    )
                    logfile.write(logline)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('Lack of parameters, example: python3 Server.py host_num port_num.')
    s = Server(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))