import socket
import time
import sys
import base64

from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA


random_generator = Random.new().read
if __name__ == '__main__':
    # 创建socket对象
    server_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
    # 获取本地主机名
    host = socket.gethostname()
    port = 9199

    # 绑定端口号
    server_socket.bind((host, port))

    # 设置最大连接数，超过后排队
    server_socket.listen(5)
    print("wait....")
    while True:

        # 建立客户端连接
        client_socket, addr = server_socket.accept()

        print("连接地址: %s" % str(addr))
        # Step 1
        print("\n============ Step 1 ============")
        print("接收消息！")
        encrypt_text = client_socket.recv(4096)
        with open("server-private.pem") as f:
            key = f.read()
            rsakey = RSA.importKey(key)
            cipher = Cipher_pkcs1_v1_5.new(rsakey)
            N1_ID = cipher.decrypt(base64.b64decode(encrypt_text), random_generator)

        N1, ID = N1_ID.decode('utf-8')[0:10], N1_ID.decode('utf-8')[10:]
        print("来自客户端的挑战：N1 = {}\n"
              "来自客户端的标识：ID = {}".format(N1,ID))
        time.sleep(1)
        N2 = str(time.time())[0:10]
        msg = N1+N2
        # print("msg\t", msg)

        # Step 2 发送

        print("\n============ Step 2 ============")
        print("发送消息!")
        print("来自客户端的挑战：N1 = {}\n"
              "来自服务器的挑战：N2 = {}".format(N1,N2))

        with open('client-public.pem') as f:
            key = f.read()
            rsakey = RSA.importKey(key)
            cipher = Cipher_pkcs1_v1_5.new(rsakey)
            cipher_text = base64.b64encode(cipher.encrypt(msg.encode('utf-8')))
        client_socket.send(cipher_text)

        # Step 3 接受

        encrypt_text_3 = client_socket.recv(4096)

        print("\n============ Step 3 ============")
        print("接收消息！")

        with open("server-private.pem") as f_3:
            key_3 = f_3.read()
            rsakey_3 = RSA.importKey(key_3)
            cipher_3 = Cipher_pkcs1_v1_5.new(rsakey_3)
            N2_ = cipher_3.decrypt(base64.b64decode(encrypt_text_3), random_generator)
            print("N2 = ", N2_.decode('utf-8'))

        if N2_.decode('utf-8') == N2:
            print("N2的值匹配正确，认定为client!")
        else:
            print("N2的值匹配失败，认定client失败！")
            break
        # Step 接受

        client_socket.close()