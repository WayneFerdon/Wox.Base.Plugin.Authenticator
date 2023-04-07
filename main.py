import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from WoxPluginBase_Query import *
from AuthenticatorClient import *

from qrcode.image.pure import PyPNGImage

class Authenticator(QueryPlugin):
    def query(self, query:str):
        results = list[QueryResult]()
        icon = QueryPlugin.defaultIcon
        first_query = query.split(' ')[0]
        if first_query == 'add':
            args = AuthenticatorClient.load_args(query.split(' '))
            name = args[Args.Name]
            issuer = args[Args.Issuer]
            secret = args[Args.Secret]
            context = f'-i {issuer} -n {name} -s {secret} -qr'
            if issuer is None:
                issuer = '-i <issuer>'
            if name is None:
                name = '-n <name>'
            if secret is None:
                secret = '-s <secret>'
            title = f'Add new otp: {issuer}({name})'
            subtitle = f'Secret: {secret}'
            results.append(QueryResult(title, subtitle, icon, context, self.add_otp.__name__,True, context).toDict())
            return results

        verify_datas = AuthenticatorClient.run(['-now'])
        for data in verify_datas:
            title = f'{data.issuer}({data.name})'
            subtitle = f'{data.code}\t{data.remain_time}'
            context = f'-i "{data.issuer}" -n "{data.name}" -s {data.secret}'
            results.append(QueryResult(title, subtitle, icon, context, self.copyData.__name__,True, data.code+'.').toDict())
            # copyData has bug while passing data to the launcher, so a '.' is added while copying data.code
        
        if query is None or query == '':
            return results
        regex = RegexList(query)
        temp = list[QueryResult]()
        for result in results:
            if regex.match(result['Title'] + result['SubTitle']):
               temp.append(result)
        return temp
    
    def add_otp(self, args:str):
        AuthenticatorClient.run(args.split(' '))

    def delete_otp(self, save:str):
        save = json.loads(save)

        with open('./generated/saved.json','r',encoding='utf-8') as f:
            saved = list(json.loads(f.read()))
        temp = list()
        for each in saved:
            name = each['Name']
            issuer = each['Issuer']
            if f'{name}' != save['Name']:
                temp.append(each)
                continue
            if f'{issuer}' != save['Issuer']:
                temp.append(each)
                continue
            if each['Secret'] != save['Secret']:
                temp.append(each)
                continue
        with open('./generated/saved.json','w',encoding='utf-8') as f:
            f.write(json.dumps(temp))
        os.remove('./generated/' + save['QR'])


    @staticmethod
    def get_saved_info(args:str):
        args = AuthenticatorClient.load_args(args.split(' '))
        with open('./generated/saved.json','r',encoding='utf-8') as f:
            saved = list(json.loads(f.read()))
        for save in saved:
            name = save['Name']
            issuer = save['Issuer']
            if f'"{name}"' != args[Args.Name]:
                continue
            if f'"{issuer}"' != args[Args.Issuer]:
                continue
            if save['Secret'] != args[Args.Secret]:
                continue
            return save

    def open_qr(self, qr:str):
        os.system('start ./generated/' + qr)
        return
    
    def context_menu(self, args:str) -> list[QueryResult]:
        save = Authenticator.get_saved_info(args)
        qr = save['QR']
        return [
            QueryResult('Open QRCode', qr, self.defaultIcon, None, self.open_qr.__name__, True, qr).toDict(),
            QueryResult('Delete otp',args,self.defaultIcon,None,self.delete_otp.__name__,True, json.dumps(save)).toDict()
        ]

if __name__ == '__main__':
    Authenticator().query('')
    # Authenticator().delete_otp('{"test":"test2"}')