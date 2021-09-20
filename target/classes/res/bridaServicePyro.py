# -*- coding: utf-8 -*-
import frida
import codecs
import Pyro4
import sys
import json
import urllib
import threading
import requests
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

#reload(sys)   
#sys.setdefaultencoding('utf-8')

# global value
g_script = None
g_forward_ip = None
g_forward_port = None
g_proxy = None

class Unbuffered(object):
   def __init__(self, stream):
       self.stream = stream
   def write(self, data):
       self.stream.write(data)
       self.stream.flush()
   def writelines(self, datas):
       self.stream.writelines(datas)
       self.stream.flush()
   def __getattr__(self, attr):
       return getattr(self.stream, attr)

# 由于同一时间只会有一个 script 在生效，因此只需要一个 callback 就可以了
# todo 但是这种使用 global 的方式也还是不是太友好，需要设计一下
def get_messages_from_js(message, data):
    if message['type'] == 'send':
        if type(message['payload']) == dict and message['payload']['from'] == 'jscode':
            # bridge to TransferServer

            payload = message['payload']['payload']
            msg_type = message['payload']['msg-type']

            resp = requests.post(
                'http://%s:%d/apiforward' % (g_forward_ip,g_forward_port),
                proxies=g_proxy,
                headers={'content-type': 'text/plain','msg-type':message['payload']['msg-type']},
                data=message['payload']['payload'])
            g_script.post({'type': 'python_send', 'payload': resp.content.decode()})  # 这种编码对于二进制格式的数据，是不是有影响
        else:
            print("[*] {0}".format(message['payload']))
    else:
        #print(message)
        pass

@Pyro4.expose
class BridaServicePyro:
    # 同一时间只会有一个 script 在生效
    def __init__(self, daemon):
        self.daemon = daemon
        self.forward_server = None
        self.pid = None
        self.device = None
        self.session = None
        self.sel = None
        self.application_id = None
        self.frida_script = None
        self.burp_proxy_host = None
        self.burp_proxy_port = None

    def attach_application(self,pid,frida_script,device_type):
        # todo: 如果需要 转发，则检查 server 是否启动，如果没有启动，则需要先启动
        self.frida_script = frida_script

        if pid.isnumeric():
            self.pid = int(pid)
        else:
            self.pid = pid

        if device_type == 'remote':
            self.device = frida.get_remote_device()
        elif device_type == 'usb':
            self.device = frida.get_usb_device()
        else:
            self.device = frida.get_local_device()

        self.session = self.device.attach(self.pid)

        with codecs.open(self.frida_script, 'r', 'utf-8') as f:
            source = f.read()

        self.script = self.session.create_script(source)
        self.script.on('message',get_messages_from_js)
        global g_script
        g_script = self.script
        self.script.load()

        return True

    def spawn_application(self,application_id,frida_script,device_type):
        # todo: 如果需要 转发，则检查 server 是否启动，如果没有启动，则需要先启动
        self.application_id = application_id
        self.frida_script = frida_script
        if device_type == 'remote':
            self.device = frida.get_remote_device()
        elif device_type == 'usb':
            self.device = frida.get_usb_device()
        else:
            self.device = frida.get_local_device()

        print(self.device)
        print(self.application_id)
        self.pid = self.device.spawn([self.application_id])
        print(self.pid)
        self.session = self.device.attach(self.pid)
        print(self.session)
        with codecs.open(self.frida_script, 'r', 'utf-8') as f:
            source = f.read()

        self.script = self.session.create_script(source)
        self.script.on('message',get_messages_from_js)
        global g_script
        g_script = self.script
        self.script.load()

        return True

    def resume_application(self):
        if self.device != None:
            self.device.resume(self.pid)
            return True
        else:
            return False

    def reload_script(self):
        with codecs.open(self.frida_script, 'r', 'utf-8') as f:
            source = f.read()

        if self.session != None:
            self.script = self.session.create_script(source)
            self.script.on('message',get_messages_from_js)
            global g_script
            g_script = self.script
            self.script.load()
            return True
        else:
            return False

    def disconnect_application(self):
        if self.device != None:
            self.device.kill(self.pid)
            return True
        else:
            return False

    def detach_application(self):
        if self.session != None:
            self.session.detach()
            self.session = None
            return True
        else:
            return False

    def launch_server(self, forward_host, forward_port):
        # 基础的类型检测工作都放到 java 里面做
        if self.forward_server == None:
            self.forward_server = MyServer(forward_host,forward_port)
            self.forward_server.start()
            global g_forward_ip,g_forward_port
            g_forward_ip = forward_host
            g_forward_port = int(forward_port)
            print("server started")
            return True
        else:
            return False


    def stop_server(self):
        if self.forward_server != None and self.forward_server.is_alive():
            self.forward_server.stop()
            self.forward_server = None
            global g_forward_ip,g_forward_port
            g_forward_ip = None
            g_forward_port = None
            # 如果 hook 需要转发，则在停止 server 时detach
            # 不放到这里做了～ burp 里面判定，如果server 没有启动就不让执行 需要 forward server 的 hook
            #self.detach_application()
            print("server stoped")
            return True
        else:
            return False

    def set_proxy(self, proxy):
        global g_proxy
        g_proxy = json.loads(proxy)

    def get_server_status(self):
        if self.forward_server != None and self.forward_server.is_alive():
            return True
        else:
            return False

    def callexportfunction(self, methodName, args):
        method_to_call = getattr(self.script.exports, methodName)

        # Take the Java list passed as argument and create a new variable list of argument
        # (necessary for bridge Python - Java, I think)
        s = []
        for i in args:
            s.append(i)

        return_value = method_to_call(*s)
        return return_value

    @Pyro4.oneway
    def shutdown(self):
        print('shutting down...')
        self.stop_server()
        self.detach_application()
        self.daemon.shutdown()

'''
    transit server thread
'''
class HttpHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path,args=urllib.parse.splitquery(self.path)
        #print(path,args)
        self._response(path, args)

    def do_POST(self):
        data_type = self.headers['msg-type']
        data = self.rfile.read(int(self.headers['content-length'])).decode("utf-8")
        #print(data_type,data)
        self._response(self.path, data)

    def _response(self, path, args):
        self.send_response(200)
        self.send_header('Content-type', 'text/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        if args == None:
            self.wfile.write(b"")
        else:
            self.wfile.write(args.encode('utf-8'))

class MyServer(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.host = host
        self.port = int(port)

    def run(self):
        self.server = ThreadingHTTPServer((self.host, self.port), HttpHandler)
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

# Disable python buffering (cause issues when communicating with Java...)
sys.stdout = Unbuffered(sys.stdout)
sys.stderr = Unbuffered(sys.stderr)

host = sys.argv[1]
port = int(sys.argv[2])
daemon = Pyro4.Daemon(host=host,port=port)

#daemon = Pyro4.Daemon(host='127.0.0.1',port=9999)
bs = BridaServicePyro(daemon)
uri = daemon.register(bs,objectId='BridaServicePyro')

print("Ready.")
daemon.requestLoop()
