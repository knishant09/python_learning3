import json, re, requests
import paramiko
from paramiko.ssh_exception import AuthenticationException, SSHException




class OSdetails():

    SSH_RETRY_INTERVAL = 30

    def __init__(self, **kwargs):
        cmd = kwargs['cmd']
        self.cmd = cmd
        self.remoteapi = "http://192.168.1.93:8000/api/remoteCommand"
        self.headers = {'content-type': 'application/json'}
		self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._ssh.connect(self.host, self.port, self.username, self.password)



    def mode_type(self):
        try:
            data = self.call_remoteapi([self.cmd[0]])
            return data
        except Exception as e:
            return False


    def os_version(self):

        try:
            data = self.call_remoteapi([self.cmd[1]])
            return data
        except Exception as e:
            return False

    def call_remoteapi(self, cmd):
        print(cmd)
        inputJSON = {}
        inputJSON['ip'] = "192.168.100.91"
        inputJSON['userName'] = "megha"
        inputJSON['password'] = "megha!234"
        inputJSON['port'] = 22
        inputJSON['command'] = cmd
        response = requests.post(url=self.remoteapi, data=json.dumps(inputJSON), headers=self.headers)
        if response.status_code == 200:
            data = response.json()
            return data["commandsOutputs"]

    def slx_status(self):

        try:
            data = self.call_remoteapi([self.cmd[2]])
            return data
        except Exception as e:
            return False


    def firewall_status(self):
        ov = self.os_version()
        ov = str(re.findall('\d+\.\d+', str(ov)))
        try:
            if ov[2] == "7":
                print("*******")
                cmd1 = "/usr/bin/systemctl status firewalld | grep -i 'Active' | awk '{print $2}'"
                data = self.call_remoteapi([cmd1])
                return data

            elif ov[2] == "6":
                cmd1 = "echo 'megha.jeos' | su - root -c /etc/init.d/iptables status"
                data = self.call_remoteapi([cmd1])
                return data

        except Exception as e:
            return False

    def java_status(self):

        try:
            data = self.call_remoteapi([self.cmd[3]])
            return data
        except Exception as e:
            return False


    def date_status(self):

        try:
            data = self.call_remoteapi([self.cmd[4]])
            return data
        except Exception as e:
            return False


    def root_status(self):
        rt_pass = ['megha.jeos', 'app.jeos', 'root123']

        for rt_pwd in rt_pass:
            root_det = "echo {} | su - root -c".format(rt_pwd)
            cmd1 = " " + root_det + " 'grep -inr 'Root' /etc/ssh/sshd_config' | head -1"
            print(cmd1)

            self._remote = RemoteCommand(host=kwargs['host'], user=kwargs['userName'], password=kwargs['password'], port=22)
            stdin, stdout, stderr = self._ssh.exec_command(cmd1)
            find_root = stdout.readlines()
            find_root = str(find_root)
            search = "Root"
            if search in find_root:
                print("Äble to access")
                break

        print("*************", find_root)


    def port_status(self):
        try:
            print(self.mode_type())
            port_lst = [9999, 1111,7443]
            listen_list = {}
            for port in port_lst:
                cmd1 = "/usr/bin/netstat -lntu | grep -i {}".format(port)
                cmd1 = " " + cmd1 + "| awk '{print $6}'"
                self._remote.execute(cmd1)  # query string for fetching data
                listen_list.update({port: str(self._remote.get_std_out()).rstrip("\\n']").lstrip("['")})  # output derived from query string

            print(listen_list)
            self.logger.info(listen_list)  # dumping output in logs
            return listen_list

        except Exception as e:
            self.logger.exception(e)  # dumping exception in logs
            return False


    def timezone_status(self):
        try:
            if self.os_version() == "7" or re.search('7.\d+\.?', self.os_version()) != None:
                cmd1 = "/usr/bin/timedatectl | grep -i 'Time zone'"
                self._remote.execute(cmd1)
                tz_stat = str(self._remote.get_std_out()).rstrip("\\n']").lstrip("['").strip()
                self.logger.info(tz_stat)  # dumping output in logs
                return tz_stat

            if re.search('6.\d+\.?', self.os_version()) != None:
                cmd1 = "date | awk '{print $5}'"
                self._remote.execute(cmd1)
                tz_stat = str(self._remote.get_std_out()).rstrip("\\n']").lstrip("['")
                self.logger.info(tz_stat)  # dumping output in logs
                return tz_stat


        except Exception as e:
            self.logger.exception(e)  # dumping exception in logs
            return False

    def user_status(self):

        try:
           data = self.call_remoteapi([self.cmd[5]])
           return data
        except Exception as e:
            return False


    def linux_type_status(self):

        try:
            data = self.call_remoteapi([self.cmd[6]])
            return data
        except Exception as e:
            return False


    def app_version(self):

        try:
            data = self.call_remoteapi([self.cmd[7]])
            return data
        except Exception as e:
            return False


    def osdetails_info(self):

        status = None
        try:
            status = self.create_json()

        except Exception as e:
            return False

        return status

    def create_json(self):

        osdetails = {}

        get_func_list = [self.mode_type, self.app_version, self.slx_status, self.firewall_status, self.java_status,
                         self.linux_type_status, self.date_status, self.timezone_status, self.os_version,
                         self.port_status,self.root_status, self.user_status]

        get_func_list = [self.mode_type, self.app_version, self.slx_status, self.java_status,self.linux_type_status, self.date_status, self.os_version, self.user_status, self.firewall_status]

        for func in get_func_list:
            print("***calling Function :", func.__name__)
            t = func()
            osdetails.update({func.__name__: t})
            osdetail = json.dumps(osdetails)

        return osdetail




def main():
    #Passing values are IP, Username, password, Port and Target type (ova/rpm)
    cmd = ["grep -i 'app.mode' /usr/local/megha/conf/app.properties", "cat /etc/system-release",
           "/usr/sbin/sestatus | head -1 | awk '{print $3}'", "/usr/bin/java -version 2>&1 | head -1",
           "date", "ls /usr/local/megha/conf/users | grep -v 'template' | awk '{print $1}'", "cat /etc/system-release",
           "grep -i 'app.version' /usr/local/megha/conf/app.properties"]
    print(len(cmd))
    #obj = ova_rpm_details(host="192.168.33.206",userName="megha",password="megha!234",port=22,cmd=cmd,target="ova")
    #obj.osdetails_info()
    obj1 = OSdetails(cmd=cmd)
    print(obj1.create_json())


if __name__ == "__main__":
    main()

