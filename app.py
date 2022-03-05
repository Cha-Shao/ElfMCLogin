from datetime import timedelta
from flask import Flask, session, request
from flask_cors import CORS
from hashlib import sha256
import os, pymysql, re

app = Flask(__name__)
# 加密key
app.secret_key = os.environ.get('session_key')
app.config.update(
    SESSION_COOKIE_SAMESITE=None,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True
)
CORS(app, supports_credentials=True)
@app.route('/')
def index():
    accountData = session.get('account_data')
    if not accountData:
        return "{'code': 400, 'msg': '未登录'}"
    return "{'code': 200, 'msg': '登录成功', 'user': session.get('account_data')}"

@app.route('/login',methods=['POST'])
def login():
    post_data = request.get_json()
    inputUser = post_data['user']
    inputPassword = post_data['pwd']

    # return "{'code': -1, 'msg': '参数不合法'}"

    if inputUser == None:
        return "{'code': -1, 'msg': '参数不合法'}"
    if len(re.findall("(?:')|(?:--)|(/\\*(?:.|[\\n\\r])*?\\*/)|(\\b(select|update|union|and|or|delete|insert|trancate|char|into|substr|ascii|declare|exec|count|master|into|drop|execute)\\b)", inputUser)) != 0:
        return "{'code': -500, 'msg': '非法字符'}"
    else:
        pass

    try:
        mysqlConfigs = pymysql.connect(
            # mysql配置
            # 在scf设置环境变量
            host=os.environ.get('sql_host'),
            port=3306,
            user=os.environ.get('sql_username'),
            password=os.environ.get('sql_password'),
            db=os.environ.get('sql_db')
        )
        cursor = mysqlConfigs.cursor()
        # 数据库命令
        command = 'SELECT * FROM ' + os.environ.get('sql_db') +' WHERE realname=%s'
        print(command,flush=True)
        checkName = [inputUser]
        cursor.execute(command, checkName)
        print(command,checkName)
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
        
    except Exception as error:
        print(error)
        return "{'code': -500, 'msg': '这个账号好像没有注册呢...'}"
        

    # 未登录判断
    # 成功
    if finallyhash == hashedPassword:
        # 设置session
        session['account_data'] = inputUser
        session.permanent = True
        app.permanent_session_lifetime = timedelta(days=7)
        return "{'code': 200,'msg': '登录成功'}"
    # 失败
    else:
        return "{'code': 400,'msg': '登录失败'}"
    
app.run(debug=True, port=9000, host='0.0.0.0')