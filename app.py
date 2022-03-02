from datetime import timedelta
from flask import Flask, session, request
from flask_cors import CORS
from ruamel import yaml
from hashlib import sha256
import os, sys, pymysql, re

folder = os.path.dirname(os.path.realpath(sys.argv[0]))
yamlPath = os.path.join(folder,'mysqlConfigs.yaml')
configData = yaml.safe_load(open(yamlPath,'r',encoding='utf-8').read())

app = Flask(__name__)
# 加密key
app.secret_key = configData['mysqlConfigs']['secretkey']
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True
)
CORS(app, supports_credentials=True)

@app.route('/')
def index():
    accountData = session.get('account_data')
    if not accountData:
        return {'code': 400, 'msg': '未登录'}
    return {'code': 200, 'msg': '登录成功', 'user': session.get('account_data')}

@app.route('/login',methods=['POST'])
def login():
    post_data = request.get_json()
    inputUser = post_data['user']
    inputPassword = post_data['pwd']

    if inputUser == None:
        return {'code': -1, 'msg': '参数不合法'}
    if len(re.findall("(?:')|(?:--)|(/\\*(?:.|[\\n\\r])*?\\*/)|(\\b(select|update|union|and|or|delete|insert|trancate|char|into|substr|ascii|declare|exec|count|master|into|drop|execute)\\b)", inputUser)) != 0:
        return {'code': -500, 'msg': '非法字符'}
    else:
        pass
    try:
        mysqlConfigs = pymysql.connect(
            # mysql配置
            host=configData['mysqlConfigs']['host'],
            port=configData['mysqlConfigs']['port'],
            user=configData['mysqlConfigs']['user'],
            password=configData['mysqlConfigs']['password'],
            db=configData['mysqlConfigs']['db'],
            charset='utf8'
        )
        cursor = mysqlConfigs.cursor()
        # 数据库命令
        command = 'SELECT * FROM '+configData['mysqlConfigs']['db']+' WHERE realname=%s'
        checkName = [inputUser]
        print('')
        print(inputUser, inputPassword)
        print(command, checkName)
        print('')
        cursor.execute(command, checkName)
        data = cursor.fetchall()
        # 从数据库拿
        for row in data:
            hashedPassword = row[3]
            salt = hashedPassword.split('$')[2]
        mysqlConfigs.close()

        # 加密
        firsthash = sha256(str(inputPassword).encode('utf-8')).hexdigest()
        salted = firsthash+salt
        secondhash = sha256(salted.encode('utf-8')).hexdigest()
        finallyhash = '$SHA$'+salt+'$'+secondhash
        
    except Exception as error: # 寄了
        print(error)
        return {'code': -500, 'msg': '这个账号好像没有注册呢...', 'pwd': checkName}
        

    # 未登录判断
    # 成功
    if finallyhash == hashedPassword:
        # 设置session
        session['account_data'] = inputUser
        session.permanent = True
        app.permanent_session_lifetime = timedelta(days=7)
        return {
            'code': 200,
            'msg': '登录成功',
        }
    # 失败
    else:
        return {
            'code': 400,
            'msg': '登录失败'
        }

if __name__ == "__main__": # 呐呐呐
    app.run(debug=True, host="127.0.0.1", port=9000)