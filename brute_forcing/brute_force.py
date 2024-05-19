import subprocess


class BruteForcer:
    def __init__(self, host, port, protocol):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.usernames_path = './datasources/usernames.txt'
        self.passwords_path = './datasources/passwords.txt'
        self.found_path = "./found.txt"

    def try_brute(self):
        subprocess.run(
            ["hydra", "-V", "-I", "-f", "-o", self.found_path,
             "-L", self.usernames_path, '-P',
             self.passwords_path, '-s', f'{self.port}',
             f'{self.protocol}://{self.host}'])
        file = open(self.found_path, 'r')
        data = file.read()
        file.close()
        open(self.found_path, 'w').close()
        if data == '':
            return []
        a = data.split('Hydra')[-1].split('login')[1].split(' ')

        return [a[1], a[-1]]

if __name__ == '__main__':
    bruter = BruteForcer("127.0.0.1", 22, "ssh", )
    print(bruter.try_brute())

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
