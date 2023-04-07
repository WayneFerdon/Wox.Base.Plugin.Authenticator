# ----------------------------------------------------------------
# Author: WayneFerdon wayneferdon@hotmail.com
# Date: 2023-04-05 19:48:53
# LastEditors: WayneFerdon wayneferdon@hotmail.com
# LastEditTime: 2023-04-08 07:30:28
# FilePath: \FlowLauncher\Plugins\Wox.Base.Plugin.Authenticator\AuthenticatorClient.py
# ----------------------------------------------------------------
# Copyright (c) 2023 by Wayne Ferdon Studio. All rights reserved.
# Licensed to the .NET Foundation under one or more agreements.
# The .NET Foundation licenses this file to you under the MIT license.
# See the LICENSE file in the project root for more information.
# ----------------------------------------------------------------

import os
import sys
import traceback
import hashlib
import base64
from enum import Enum

import pyotp
from qrcode import QRCode, constants
from colorama import Fore, Back, Style

import datetime
import time
import hmac
import json

def int_to_bytestring(i, padding=8):
    result = bytearray()
    while i != 0:
        result.append(i & 0xFF)
        i >>= 8
    return bytes(bytearray(reversed(result)).rjust(padding, b'\0'))

class VerifyData():
    def __init__(self, issuer:str, name:str, secret:str,code:str, remain_time:int) -> None:
        self.issuer = issuer
        self.name = name
        self.secret = secret
        self.code = code
        self.remain_time = remain_time

    def display(self):
        output = Fore.GREEN + f"{self.issuer}({self.name})" + '\n'
        output += Fore.BLUE + "Current code: "
        output += Fore.RED + self.code + '\t'
        output += Fore.CYAN + f"Remain: {self.remain_time}s"
        output += Style.RESET_ALL
        print(output, flush=True)

class AuthenticatorClient:
    def __init__(self, secret:str=None, alias:str=False) -> None:
        self.alias = alias
        self.secret = secret
        if self.secret is None:
            self.secret = pyotp.random_base32(64)
        return
    
    @property
    def __byte_secret__(self):
        secret = self.secret
        missing_padding = len(secret) % 8
        if missing_padding != 0:
            secret += '=' * (8 - missing_padding)
        return base64.b32decode(secret, casefold=True)

    @staticmethod
    def __creat_secret_from_alias__(alias:str):
        if not alias:
            return None
        if len(alias) < 32:
            alias = alias
            secret = hashlib.sha512(alias.encode('utf-8')).digest()
            secret = base64.b32encode(secret)[:32].decode('utf-8')
        return secret

    def generate_otp(self, time_offset_sec:float = 0):
        for_time = datetime.datetime.now() + datetime.timedelta(seconds=time_offset_sec)
        input = int(time.mktime(for_time.timetuple())/30)
        if input < 0:
            raise ValueError('input must be positive integer')
        hasher = hmac.new(self.__byte_secret__, int_to_bytestring(input), hashlib.sha1)

        hmac_hash = bytearray(hasher.digest())
        offset = hmac_hash[-1] & 0xf
        code = ((hmac_hash[offset] & 0x7f) << 24 |
        (hmac_hash[offset + 1] & 0xff) << 16 |
        (hmac_hash[offset + 2] & 0xff) << 8 |
        (hmac_hash[offset + 3] & 0xff))
        
        digits = 6
        str_code = str(code % 10 ** digits)
        while len(str_code) < digits:
            str_code = '0' + str_code
        return str_code

    def create_QRCode(self, name:str, issuer:str, save:bool=True, dir:str=None):
        data = pyotp.totp.TOTP(self.secret).provisioning_uri(name=name, issuer_name=issuer)
        qr = QRCode(
            version=1,
            error_correction=constants.ERROR_CORRECT_L,
            box_size=6,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image()
        if not save:
            img.get_image().show()
            return
        
        file = f'{name}@{issuer}[Secret={self.secret}]'
        if self.alias:
            file += f'[Alias={self.alias}]'
        file += '.png'
        file = file.replace(":","：")
        
        if not dir:
            dir = os.path.dirname(os.path.abspath(__file__))
            dir = os.path.join(dir, 'generated')
            if not os.path.isdir(dir):
                os.makedirs(dir)
        path = os.path.join(dir, file)
        if os.path.isfile(path):
            return
            # print(f'image already exist: {path}')
        else:
            img.save(path)
            # print(f'image saved: {path}')
            with open('./generated/saved.json','r',encoding='utf-8') as f:
                saved = list(json.loads(f.read()))
                save = dict()
                save['Name'] = name
                save['Issuer'] = issuer
                save['Secret'] = self.secret
                save['QR'] = file
                saved.append(save)
            with open('./generated/saved.json','w',encoding='utf-8') as f:
                f.write(json.dumps(saved))
        return
    
    def verify(self, code):
        return pyotp.TOTP(self.secret).verify(code)
    
    @staticmethod
    def load_args(argv:list[str]):
        args = dict().fromkeys(Args.all)
        for arg in Args.bools:
            args[arg] = False

        current = None
        for v in argv:
            if current is not None:
                args[current] = v
                current = None
                continue
            arg = Args.get(v)
            if not arg:
                continue
            if arg in Args.bools:
                args[arg] = True
            else:
                current = arg
        return args

    @staticmethod
    def get_saved():
        with open('./generated/saved.json','r',encoding='utf-8') as f:
            saved = json.loads(f.read())
        infos = list()
        for each in saved:
            name = each["Name"] if "Name" in each.keys() else None
            issuer = each["Issuer"] if "Issuer" in each.keys() else None
            secret = each["Secret"] if "Secret" in each.keys() else None
            infos.append([name, issuer, secret])
        return infos

    @staticmethod
    def update_now(infos, is_display:bool):
        results = list[VerifyData]()
        for each in infos:
            name, issuer, secret = each
            display = '-display' if is_display else ''
            args = ['-n', name, '-i', issuer, '-s', secret,display,'-qr','-g']
            results += AuthenticatorClient.run(args)
        return results
    
    @staticmethod
    def get_secret_from_args(args):
        # priority: file > secret > alias
        is_display = args[Args.Display]
        alias = args[Args.Alias]
        secret = args[Args.Secret]
        file = args[Args.Secret_file]
        if file:
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    secret = f.read()
            except Exception:
                if is_display:
                    traceback.format_exc()
        if not secret:
            secret = AuthenticatorClient.__creat_secret_from_alias__(alias=alias)
        if is_display:
            print(f'Secret: {secret}')
        return secret, alias
    
    def gen_code_from_args(self, args):
        name = args[Args.Name]
        issuer = args[Args.Issuer]
        is_display = args[Args.Display]
        remain_time = 30 - datetime.datetime.now().second % 30
        verify_data = VerifyData(issuer, name, self.secret, self.generate_otp(), remain_time)
        if is_display:
            verify_data.display()
        return verify_data
        
    @staticmethod
    def run(argv=sys.argv) -> list[VerifyData]:
        args = AuthenticatorClient.load_args(argv)
        is_display = args[Args.Display]
        if args[Args.Now] == True:
            infos = AuthenticatorClient.get_saved()
            now = AuthenticatorClient.update_now(infos, is_display)
            # while args[Args.Update]:
            #     time.sleep(1)
            #     now = AuthenticatorClient.update_now(infos, is_display)
            return now
        # get secret and client
        
        secret, alias = AuthenticatorClient.get_secret_from_args(args)
        client = AuthenticatorClient(secret=secret, alias=alias)
        
        verify_data = client.gen_code_from_args(args)
        if args[Args.GenOnly]:
            return [verify_data]
        client.create_QRCode(
            name=args[Args.Name],
            issuer=args[Args.Issuer],
            save=args[Args.SaveQR],
            dir=args[Args.QRPath]
        )
            
        if not args[Args.Verify]:
            return [verify_data]
        code = input('Please enter verify code: ')
        max_count = 5
        for i in range(max_count-1):
            if client.verify(code=code):
                if is_display:
                    print('Verification passed!')
                return None
            code = input('Failed verifying, please enter the correct code: ')
        if is_display:
            'Too many times failed, please try again.'
        return None

class Args(Enum):
    Issuer = 0
    Name = 10
    SaveQR = 20
    QRPath = 21
    Secret = 30
    Secret_file = 31
    Alias = 32
    Verify = 40
    GenOnly = 50
    Now = 51
    Update = 52
    Display = 60

    __all__ = None
    __bools__ = None

    @classmethod
    @property
    def all(cls):
        if cls.__all__ is not None:
            return cls.__all__
        cls.__all__ = {
            Args.Secret_file:['-sf', '-secret_file'],
            Args.Secret:['-s', '-secret'],
            Args.Name:['-n', '-name'],
            Args.Issuer:['-i', '-issuer'],
            Args.Verify:['-v', '-verify'],

            Args.SaveQR:['-qr', '-save_qr'],
            Args.QRPath:['-qd', '-qr_dir'],

            Args.GenOnly:['-g', '-generate'],
            Args.Now:['-now'],
            Args.Update:['-u'],
            Args.Alias:['-a', '-alias'],
            Args.Display:['-display']
        }
        return cls.__all__
    
    @classmethod
    @property
    def bools(cls):
        if cls.__bools__ is not None:
            return cls.__bools__
        cls.__bools__ = [
            Args.SaveQR,
            Args.GenOnly,
            Args.Now,
            Args.Update,
            Args.Display,
        ]
        return cls.__bools__

    @classmethod
    def get(cls, key:str):
        'Return the value for key if key is in the dictionary, else None'
        for opt in cls:
            if key in cls.all[opt]:
                return opt
        return None
    
if __name__ == '__main__':
    AuthenticatorClient.run()