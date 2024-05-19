import subprocess
import shlex
import time

class BruteForcer:
    def __init__(self, host, port, protocol):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.user_names_path = '.user_names.txt'
        self.passwords_path = '.passwords.txt'

    def brute_force(self):
        command = f'hydra -L {self.user_names_path} -P {self.passwords_path} {self.protocol}://{self.host}:{self.port}'
        p = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1)
        p.kill()
        stdout, stderr = p.communicate()
        print(stdout.decode())


bruter = BruteForcer("127.0.0.1", 23, "telnet")
bruter.brute_force()

