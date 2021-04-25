'''
@author: Zhi Ye (z5314977)
@version: python3
'''
import socket
import sys
import time
import threading
import re


class Server:
    def __init__(self, host, port, failed_num):
        self.login = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen()
        self.login_log = {}
        self.msg_log = {}
        self.block = {}
        print('Server started...')
        while True:
            client, address = self.sock.accept()
            # activate threading to connect mutiple user
            thread = threading.Thread(target=self.tcpConnect, args=(client, address, failed_num))
            thread.start()

    def tcpConnect(self, client, address, failed_num):
        login = False
        cnt = 0
        while not login:
            message = client.recv(1024)
            username = message.decode().split(',')[0]
            password = message.decode().split(',')[1]
            udp_port = message.decode().split(',')[2]
            # check if user is block and if it is time to unblock
            if self.isBlock(address):
                client.send('2'.encode())
                break
            if self.isValidLogin(username, password):
                print('{} Login'.format(username))
                client.send('0'.encode())  # 0 stands for login successfully
                login = True
                self.login_log[username] = [time.strftime('%d %b %Y %H:%M:%S'), address[0], udp_port]
                self.updateUserLog()
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
            # logout command
            if re.match('OUT', afterLoginMsg.decode()):
                if len(afterLoginMsg.decode()) != 3:
                    client.send('Invalid command of OUT, cannot add anything after "OUT".'.encode())
                self.login_log.pop(username)
                self.updateUserLog()
                login = False
                print('{} Logout'.format(username))
                client.send('Bye! {}'.format(username).encode())
                client.close()
            elif re.match('MSG', afterLoginMsg.decode()):
                # check if MSG command is valid
                if len(afterLoginMsg.decode()) == 3 or afterLoginMsg.decode()[4:] == '':
                    client.send('Invaid command of MSG, message cannot be empty.'.encode())
                elif ';' in afterLoginMsg.decode()[4:]:
                    client.send('Invalid symbol of message, cannot use ";" in message.'.encode())
                else:
                    msg = afterLoginMsg.decode()[4:]
                    postTime = time.strftime('%d %b %Y %H:%M:%S')
                    self.msg_log[postTime] = [username, msg, 0]
                    self.updateMsgLog(username)
                    # msgIndex = list(self.msg_log).index(msgId) + 1
                    msgIndex = list(self.msg_log).index(postTime) + 1
                    client.send('Message #{} posted at {}.'.format(msgIndex, postTime).encode())
                    print('{} posted MSG #{} "{}" at {}'.format(username, msgIndex, msg, postTime))
            elif re.match('DLT', afterLoginMsg.decode()):
                pattern = re.compile(r'#\d+')
                valid, validMsg = self.isValid(afterLoginMsg.decode(), username)
                if valid:
                    msgIndex = pattern.findall(afterLoginMsg.decode())[0]
                    givenTime = afterLoginMsg.decode()[afterLoginMsg.decode().index(msgIndex) + len(msgIndex) + 1:]
                    deleteMsg = self.msg_log[givenTime][1]
                    self.msg_log.pop(givenTime)
                    self.updateMsgLog(username)
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
            elif re.match('EDT', afterLoginMsg.decode()):
                pattern = re.compile(r'#\d+')
                valid, validMsg = self.isValid(afterLoginMsg.decode(), username)
                if valid:
                    msgIndex = pattern.findall(afterLoginMsg.decode())[0]
                    givenTime = afterLoginMsg.decode()[
                                afterLoginMsg.decode().index(msgIndex) + len(msgIndex) + 1:afterLoginMsg.decode().index(
                                    msgIndex) + len(msgIndex) + 1 + 20]
                    newMsg = afterLoginMsg.decode()[afterLoginMsg.decode().index(msgIndex) + len(msgIndex) + 1 + 21:]
                    editTime = time.strftime('%d %b %Y %H:%M:%S')
                    listMsg = list(self.msg_log)
                    newMsgLog = {}
                    for idx in range(len(self.msg_log)):
                        if idx == listMsg.index(givenTime):
                            newMsgLog[editTime] = [username, newMsg, 1]
                        else:
                            newMsgLog[listMsg[idx]] = self.msg_log[listMsg[idx]]
                    self.msg_log = newMsgLog
                    self.updateMsgLog(username)
                    print('{} edited MSG {} "{}" at {}.'.format(
                        username,
                        msgIndex,
                        newMsg,
                        editTime
                    ))
                    client.send('Message {} edited at {}'.format(
                        msgIndex,
                        editTime
                    ).encode())
                else:
                    client.send(validMsg.encode())
            elif re.match('RDM', afterLoginMsg.decode()):
                givenTime = afterLoginMsg.decode()[4:24]
                print('{} issued RDM command'.format(username))
                print('Return messages:')
                if givenTime >= max(self.msg_log) or len(self.msg_log) == 0:
                    print('No new message')
                    client.send('No new message'.encode())
                elif givenTime < max(self.msg_log) and len(self.msg_log) != 0 and len(givenTime) == 20:
                    returnMsg = ''
                    for (idx, key) in enumerate(self.msg_log):
                        if key > givenTime:
                            returnMsg += '#{} {}, {}, edited at {}.\n'.format(
                                idx + 1,
                                self.msg_log[key][0],
                                self.msg_log[key][1],
                                key
                            )
                            print('#{} {}, {}, edited at {}.'.format(
                                idx + 1,
                                self.msg_log[key][0],
                                self.msg_log[key][1],
                                key
                            ))
                    client.send(returnMsg.encode())
                else:
                    client.send('Invalid timestamp, please checked'.encode())
            elif re.match('ATU', afterLoginMsg.decode()):
                if len(afterLoginMsg.decode()) > 3:
                    client.send('Invalid command of ATU, cannot add anything after "ATU".'.encode())
                else:
                    print('{} issued ATU command'.format(username))
                    print('Return active user list:')
                    if len(self.login_log) == 1 and username in self.login_log:
                        print('\tNo other active users')
                        client.send('No other active users'.encode())
                    else:
                        returnMsg = ''
                        for key in self.login_log:
                            if key != username:
                                returnMsg += '{}, {}, {}, active since {}\n'.format(
                                    key,
                                    self.login_log[key][1],     # userlog - ip address
                                    self.login_log[key][2],     # userlog - udp port number
                                    self.login_log[key][0]      # userlog - login time
                                )
                                print('\t{}, {}, {}, active since {}'.format(
                                    key,
                                    self.login_log[key][1],  # userlog - ip address
                                    self.login_log[key][2],  # userlog - udp port number
                                    self.login_log[key][0]  # userlog - login time
                                ))
                        client.send(returnMsg.encode())
            else:
                client.send('Error. Invalid command!'.encode())


    def isValid(self, message, username):
        '''
            check if DLT and EDT commands are valid
            @param self
            @param message: {string}, decoding message received from client
            @param username: {string}, username of client
            @return: {list}, [True (or False), validation message]
        '''
        if len(message) == 3:
            return [False, 'Invalid command, cannot be empty after DLT']
        pattern = re.compile(r'#\d+')
        # check if message sequence number is valid
        if not pattern.findall(message):
            return [False, 'Invalid message number, please checked']
        msgNum = int(pattern.findall(message)[0].split('#')[1])
        # check if message sequence number is valid
        if msgNum > len(self.msg_log):
            return [False, 'Invalid message number, please checked']
        else:
            timeBeginIndex = message.index(pattern.findall(message)[0]) + len(pattern.findall(message)[0]) + 1
            lengthOfTime = 20
            givenTime = message[timeBeginIndex:timeBeginIndex + lengthOfTime]
            # check if timestamp is valid
            if givenTime not in self.msg_log:
                return [False, 'Invalid timestamp, please checked']
            # check authorization
            elif givenTime in self.msg_log and self.msg_log[givenTime][0] != username:
                return [False, 'Unauthorised to edit message #{}'.format(msgNum)]
            elif list(self.msg_log).index(givenTime) + 1 != msgNum:
                return [False, 'Invalid timestamp, please checked']
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

    def updateMsgLog(self, username):
        with open('messagelog.txt', 'w+') as file:
            for (idx, time) in enumerate(self.msg_log):
                logline = '{}; {}; {}; {}; {}\n'.format(
                    idx + 1,
                    time,
                    username,
                    self.msg_log[time][1],
                    'yes' if self.msg_log[time][2] else 'no'
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

    def updateUserLog(self):
        with open('userlog.txt', 'w+') as logfile:
            for (idx, name) in enumerate(self.login_log):
                logline = '{}; {}; {}; {}; {}\n'.format(
                    idx + 1,                    # userlog - sequence number
                    self.login_log[name][0],    # userlog - login time
                    name,                       # userlog - username
                    self.login_log[name][1],    # userlog - ip address
                    self.login_log[name][2],    # userlog - udp port number
                )
                logfile.write(logline)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('Lack of parameters, example: python3 Server.py host_num port_num.')
    elif int(sys.argv[3]) == 0 or int(sys.argv[3]) > 5:
        print('Invalid failed number, must range from 1 to 5.')
    else:
        s = Server(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))