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
            if afterLoginMsg.decode() == 'OUT':
                self.login_log.pop(username)
                self.updateUserLog()
                login = False
                print('{} Logout'.format(username))
                client.send('Bye! {}'.format(username).encode())
                client.close()
            elif 'MSG ' in afterLoginMsg.decode():
                # TODO: empty message and validation
                # print(afterLoginMsg.decode()[4:])
                msg = afterLoginMsg.decode()[4:]
                postTime = time.strftime('%d %b %Y %H:%M:%S')
                # msgId = postTime + '|' + username
                # self.msg_log[msgId] = [msg, 0]
                self.msg_log[postTime] = [username, msg, 0]
                self.updateMsgLog(username)
                # msgIndex = list(self.msg_log).index(msgId) + 1
                msgIndex = list(self.msg_log).index(postTime) + 1
                client.send('Message #{} posted at {}.'.format(msgIndex, postTime).encode())
                print('{} posted MSG #{} "{}" at {}'.format(username, msgIndex, msg, postTime))
            elif 'DLT ' in afterLoginMsg.decode():
                pattern = re.compile(r'#\d+')
                valid, validMsg = self.isValid(afterLoginMsg.decode(), username)
                if valid:
                    msgIndex = pattern.findall(afterLoginMsg.decode())[0]
                    givenTime = afterLoginMsg.decode()[afterLoginMsg.decode().index(msgIndex) + len(msgIndex) + 1:]
                    # givenId = givenTime + '|' + username
                    # deleteMsg = self.msg_log[givenId][0]
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
            elif 'EDT ' in afterLoginMsg.decode():
                pattern = re.compile(r'#\d+')
                valid, validMsg = self.isValid(afterLoginMsg.decode(), username)
                if valid:
                    msgIndex = pattern.findall(afterLoginMsg.decode())[0]
                    givenTime = afterLoginMsg.decode()[
                                afterLoginMsg.decode().index(msgIndex) + len(msgIndex) + 1:afterLoginMsg.decode().index(
                                    msgIndex) + len(msgIndex) + 1 + 20]
                    # givenId = givenTime + '|' + username
                    newMsg = afterLoginMsg.decode()[afterLoginMsg.decode().index(msgIndex) + len(msgIndex) + 1 + 21:]
                    # update and remain original order (message number)
                    editTime = time.strftime('%d %b %Y %H:%M:%S')
                    # editId = editTime + '|' + username
                    listMsg = list(self.msg_log)
                    # listMsg[listMsg.index(givenId)] = editId
                    # self.msg_log[givenId] = [newMsg, 1]
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
            elif 'RDM ' in afterLoginMsg.decode():
                givenTime = afterLoginMsg.decode()[4:24]
                # TODO: check givenTime is valid
                print('{} issued RDM command'.format(username))
                print('Return messages:')
                if givenTime > max(self.msg_log) or len(self.msg_log) == 0:
                    print('No new message')
                    client.sent('No new message'.encode())
                else:
                    returnMsg = ''
                    for (idx, key) in enumerate(self.msg_log):
                        if key > givenTime:
                            returnMsg += '\n#{} {}, {}, edited at {}.'.format(
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
            elif 'ATU' == afterLoginMsg.decode():
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
            elif 'UDP ' in afterLoginMsg.decode():
                return
            else:
                client.sent('Error. Invalid command!'.encode())

    # TODO: check if command line is valid
    def isCommandValid(self):
        return

    def isValid(self, message, username):
        pattern = re.compile(r'#\d+')
        if not pattern.findall(message):
            return [False, 'Wrong message number, please checked']
        msgNum = int(pattern.findall(message)[0].split('#')[1])
        if msgNum > len(self.msg_log):
            return [False, 'Wrong message number, please checked']
        else:
            timeBeginIndex = message.index(pattern.findall(message)[0]) + len(pattern.findall(message)[0]) + 1
            lengthOfTime = 20
            givenTime = message[timeBeginIndex:timeBeginIndex + lengthOfTime]
            # givenId = givenTime + '|' + username
            # TODO: givenTime validation
            if givenTime not in self.msg_log:
                return [False, 'Wrong timestamp, please checked']
            elif givenTime in self.msg_log and self.msg_log[givenTime][0] != username:
                return [False, 'Message does not belong to you']
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
    s = Server(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))