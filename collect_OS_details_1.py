#from api.lib.projects.HDCA.AddProbe.probeBase import BaseProbe
from datetime import datetime
import time,traceback, sys, os, platform, subprocess
import paramiko, utils, json, re, string
from paramiko.ssh_exception import AuthenticationException, SSHException



class ova_rpm_details():

    SSH_RETRY_INTERVAL = 30

    def __init__(self, host, username, password, port, target):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.target = target
        self._ssh = ""



    def ssh_connect(self):
        print(self.username)
        print(self.host)
        print(self.port)
        print(self.password)
        try:
            if self.username == "megha":
                self._ssh = paramiko.SSHClient()
                self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self._ssh.connect(self.host, self.port, self.username, self.password)

            elif self.username == "root":
                self._ssh = paramiko.SSHClient()
                self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self._ssh.connect(self.host, self.port, self.username, self.password)

        except paramiko.ssh_exception.AuthenticationException as e:
            print("check the Authentication")


    def mode_type(self):
        cmd = "grep -i 'app.mode' /usr/local/megha/conf/app.properties"
        stdin, stdout, stderr = self._ssh.exec_command(cmd)
        mode = str(stdout.readlines()).split('=')
        type = mode[1].strip("\\n']")
        return type

    def os_version(self):
        cmd = "cat /etc/system-release"
        stdin, stdout, stderr = self._ssh.exec_command(cmd)
        os_version = str(re.findall('\d+\.\d+', str(stdout.readlines()))).rstrip("']").lstrip("['")
        return os_version


    def _enable_root(self):

        print("-------------------------")
        s_r = "sed -i 's/PermitRootLogin no/PermitRootLogin yes/g' /etc/ssh/sshd_config"
        s_r = '"' + s_r + '"'

        if self.username == "megha" and self.mode_type() == "server":
            print("**********SERVER***************")
            user_det = "echo 'megha.jeos' | su - root -c"
            cmd = " " + user_det + " " + s_r + " "
            cmd1 = " " + user_det + " 'service sshd restart'"
            print(cmd)
            stdin, stdout, stderr = self._ssh.exec_command(cmd, get_pty=True)

            print(stderr.readlines())
            print(stdout.readlines())
            stdin, stdout, stderr = self._ssh.exec_command(cmd1, get_pty=True)
            print(stderr.readlines())
            t = stdout.readlines()
            print(t)




        elif self.username == "megha" and self.mode_type() == "probe":
            print("**********PROBE***************")
            user_det = "echo 'app.jeos' | su - root -c"
            cmd = " " + user_det + " " + s_r + " "
            cmd1 = " " + user_det + " 'service sshd restart'"
            #print(cmd)
            #print(cmd1)
            stdin, stdout, stderr = self._ssh.exec_command(cmd)
            stdin, stdout, stderr = self._ssh.exec_command(cmd1)
            stdout.readlines()


    def selinux_status(self):
        cmd = "/usr/sbin/sestatus | head -1 | awk '{print $3}'"
        stdin, stdout, stderr = self._ssh.exec_command(cmd)
        return str(stdout.readlines()).rstrip("\\n']").lstrip("['")


    def firewall_status(self):
        try:
            if self.os_version() == "7" or re.search('7.\d+\.?', self.os_version()) != None:
                print("*******")
                cmd = "/usr/bin/systemctl status firewalld | grep -i 'Active' | awk '{print $2}'"
                stdin, stdout, stderr = self._ssh.exec_command(cmd)
                return str(stdout.readlines()).rstrip("\\n']").lstrip("['")
            elif re.search('6.\d+\.?', self.os_version()) != None:
                print("taking firewall info")
                fwl = []
                cmd = "/etc/init.d/iptables status"
                stdin, stdout, stderr = self._ssh.exec_command(cmd)
                fwl.append(str(stdout.readlines()).lstrip("['").rstrip("']").replace("\\n", ''))
                return fwl
        except AttributeError as e:
            return None

    def java_status(self):
        cmd = "/usr/bin/java -version 2>&1 | head -1 | awk '{print $3}'"
        stdin, stdout, stderr = self._ssh.exec_command(cmd)
        return str(stdout.readlines()).rstrip("\\n']").lstrip("['").replace('\"','')

    def date_status(self):
        cmd = "date"
        stdin, stdout, stderr = self._ssh.exec_command(cmd)
        return str(stdout.readlines()).rstrip("\\n']").lstrip("['")

    def root_status(self):
        self.ssh_connect()
        rt_pass = ['megha.jeos', 'app.jeos', 'root123']
        cmd = "date"
        stdin, stdout, stderr = self._ssh.exec_command(cmd)
        print(rt_pass)
        for rt_pwd in rt_pass:
            root_det = "echo {} | su - root -c".format(rt_pwd)
            cmd1 = " " + root_det + " 'grep -inr 'Root' /etc/ssh/sshd_config' | head -1"
            print(cmd1)

            stdin, stdout, stderr = self._ssh.exec_command(cmd1)
            fd = stdout.readlines()
            print(fd)
            fd = str(fd)
            search = "Root"
            if search in fd:
                print("Äble to access")
                break

        print("*************", fd)
        print(type(fd))







        ''''
        print(self.mode_type())

        if self.target == "ova" and self.mode_type() == "server":
            root_det = "echo 'megha.jeos' | su - root -c"
            cmd = " " + root_det + " 'grep -inr 'Root' /etc/ssh/sshd_config | head -1'"
            stdin, stdout, stderr = self._ssh.exec_command(cmd)
            return str(stdout.readlines()).rstrip("\\n']").lstrip("['").split(':')[2]
        elif self.target == "ova" and self.mode_type() == "probe":
            print("*************")
            root_det = "echo 'app.jeos' | su - root -c"
            cmd = " " + root_det + " 'grep -inr 'Root' /etc/ssh/sshd_config | head -1'"
            print(cmd)
            stdin, stdout, stderr = self._ssh.exec_command(cmd)
            # print(str(stdout.readlines()).rstrip("\\n']").lstrip("['").split(':')[1])
            return str(stdout.readlines()).rstrip("\\n']").lstrip("['").split(':')[1]
        elif self.target == "rpm":
            root_det = "echo 'root123' | su - root -c"
            cmd = " " + root_det + " 'grep -inr 'Root' /etc/ssh/sshd_config | head -1'"
            stdin, stdout, stderr = self._ssh.exec_command(cmd)
            # print(str(stdout.readlines()).rstrip("\\n']").lstrip("['").split(':')[1])
            return str(stdout.readlines()).rstrip("\\n']").lstrip("['").split(':')[1]

        '''

    def port_status(self):
        if self.mode_type() == "probe":
            port_lst = [9999, 1111]
            listen_list = {}
            for port in port_lst:
                cmd = "/usr/bin/netstat -lntu | grep -i {}".format(port)
                cmd = " " + cmd + "| awk '{print $6}'"
                stdin, stdout, stderr = self._ssh.exec_command(cmd)
                listen_list.update({port: str(stdout.readlines()).rstrip("\\n']").lstrip("['")})
            return listen_list
        if self.mode_type() == "server":
            port_lst = [7443]
            listen_list = {}
            for port in port_lst:
                cmd = "netstat -lntu | grep -i {}".format(port)
                cmd = " " + cmd + "| awk '{print $6}'"
                stdin, stdout, stderr = self._ssh.exec_command(cmd)
                listen_list.update({port: str(stdout.readlines()).rstrip("\\n']").lstrip("['")})
            return listen_list


    def timezone_status(self):
        try:
            if self.os_version() == "7" or re.search('7.\d+\.?', self.os_version()) != None:
                cmd = "/usr/bin/timedatectl | grep -i 'Time zone'"
                stdin, stdout, stderr = self._ssh.exec_command(cmd)
                return str(stdout.readlines()).rstrip("\\n']").lstrip("['").strip()


            if re.search('6.\d+\.?', self.os_version()) != None:
                cmd = "date | awk '{print $5}'"
                stdin, stdout, stderr = self._ssh.exec_command(cmd)
                return str(stdout.readlines()).rstrip("\\n']").lstrip("['")
        except AttributeError as e:
            return None

    def user_status(self):
        usr = []
        cmd = "ls /usr/local/megha/conf/users | grep -v 'template'"
        stdin, stdout, stderr = self._ssh.exec_command(cmd)
        usr.append(str(stdout.readlines()).rstrip(']"').lstrip('"[').replace('\\n',''))
        return usr


    def linux_type_status(self):
        cmd = "cat /etc/system-release"
        stdin, stdout, stderr = self._ssh.exec_command(cmd)
        return str(stdout.readlines()).rstrip(']"').lstrip('["').replace('\"', '').replace('\\n','').rstrip("']").lstrip("['")

    def app_version(self):
        cmd = "grep -i 'app.version' /usr/local/megha/conf/app.properties"
        stdin, stdout, stderr = self._ssh.exec_command(cmd)
        mode = str(stdout.readlines()).split('=')
        return mode[1].strip("\\n']")

    def logged_in_users(self):
        user_lst = {"megha": "megha!234", "config": "megha!234", "meghadata": "meghadata123", "root": "megha.jeos"}
        user_log = {}

        for key,value in user_lst.items():
            cmd = ""

    def ovadetailsinfo(self):

        status = None
        try:
            print("*********Fetching ova OS details*********")
            self.ssh_connect()

            if self.mode_type() == "probe":
                self._ssh.connect(self.host, self.port, self.username, self.password)
                status = self.create_json()
            if self.mode_type() == "server":
                print("Checking OVA SERVER DETAILS")

                self._ssh.connect(self.host, self.port, self.username, self.password)
                self.firewall_status()

                status = self.create_json()
        except paramiko.ssh_exception.AuthenticationException as e:
            print("check the Target Type")

        return status

    def create_json(self):
        my_data_json = {}
        ova_probe_details = {}

        get_func_list = [self.mode_type, self.app_version, self.selinux_status, self.firewall_status, self.java_status,
                         self.linux_type_status, self.date_status, self.timezone_status, self.os_version,
                         self.port_status,self.root_status, self.user_status]

        for func in get_func_list:
            print("***calling Function :", func.__name__)
            t = func()
            ova_probe_details.update({func.__name__: t})
       # print(ova_probe_details)
        print(json.dumps(ova_probe_details))

        return ova_probe_details


    def rpm_details_info(self):
        status = None
        try:
            self.ssh_connect()
            self.os_version()
            self.mode_type()

            print("*********Fetching RPM OS details*********")
            if self.mode_type() == "probe":
                status = self.create_json()
            if self.mode_type() == "server":
                print("***SERVER IN*****")
                self.timezone_status()
                status = self.create_json()
        except paramiko.ssh_exception.AuthenticationException as e:
            print("check the Target Type")

        return status

def main():
    #Passing values are IP, Username, password, Port and Target type (ova/rpm)
    obj = ova_rpm_details("192.168.33.206", "megha", "megha!234", 22, "ova")
    obj.root_status()
   # if obj.target == "rpm":
    #    obj.rpm_details_info()
   # elif obj.target == "ova":
   #     obj.ovadetailsinfo()



if __name__ == "__main__":
    main()

