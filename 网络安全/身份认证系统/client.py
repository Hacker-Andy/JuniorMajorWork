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
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 获取本地主机名
    host = socket.gethostname()

    ip = socket.gethostbyname(host)
    ID_client = str(host)
    N1 = str(time.time())[0:10]
    # 设置端口号
    port = 9199

    # 连接服务
    s.connect((host, port))

    # Step 1
    # 以时间戳作为挑战N1，以本机主机名地址作为A的标识
    print("\n============ Step 1 ============")
    print("发送消息!")
    print("来自客户端的挑战：N1 = {}\n"
          "来自客户端的标识：ID = {}".format(N1, ID_client))
    msg = N1+ID_client  # N1||ID_A
    with open('server-public.pem') as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        cipher_text = base64.b64encode(cipher.encrypt(msg.encode('utf-8')))
    s.send(cipher_text)

    # Step 2 接受
    print("\n============ Step 2 ============")
    print("接收消息！")
    encrypt_text_2 = s.recv(4096)
    with open("client-private.pem") as f:
        key_2 = f.read()
        rsakey_2 = RSA.importKey(key_2)
        cipher_2 = Cipher_pkcs1_v1_5.new(rsakey_2)
        N1_N2 = cipher_2.decrypt(base64.b64decode(encrypt_text_2), random_generator)
        # print(N1_N2.decode('utf-8'))
    N1_, N2 = N1_N2[0:10].decode('utf-8'), N1_N2[10:].decode('utf-8')
    print("来自客户端的挑战：N1 = {}\n"
          "来自客户端的挑战：N2 = {}".format(N1_, N2))
    if N1 == N1_:
        print("N1的值匹配正确，认定为server!")
    else:
        print("N1的值匹配失败，认定server失败！")

    # Step 3
    print("\n============ Step 3 ============")
    print("发送消息!")
    print("来自服务器的挑战：N2 = ", N2)
    with open('server-public.pem') as f:
        key_3 = f.read()
        rsakey_3 = RSA.importKey(key_3)
        cipher_3 = Cipher_pkcs1_v1_5.new(rsakey_3)
        cipher_text_3 = base64.b64encode(cipher_3.encrypt(N2.encode('utf-8')))
        # print(type(cipher_text))
        # print(cipher_text.decode('utf-8'))
    s.send(cipher_text_3)

    s.close()

    # print(encrypt_text.decode('utf-8'))