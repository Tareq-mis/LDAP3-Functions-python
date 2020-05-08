from ldap3 import Server, ALL, Connection, MODIFY_REPLACE
from hashlib import *
from base64 import b64encode as encode
import re


def conn_LDAP():
    server = Server('put yours here')
    conn = Connection(server)
    return conn.bind()


def hash_sha256(string):
    return encode(sha256(string.encode('utf-8')).digest()).decode('ASCII')


def hash_sha512(string):
    return encode(sha512(string.encode('utf-8')).digest()).decode('ASCII')


def hash_MD5(string):
    return encode(md5(string.encode('utf-8')).digest()).decode('ASCII')


def hash_sha1(string):
    return encode(sha1(string.encode('utf-8')).digest()).decode('ASCII')


def get_all_entries():
    print('------------Connecting ...Please wait!!-----------')
    try:
        if conn_LDAP():
            print('-----------The connection was successful----------')
            server = Server('put yours here', get_info=ALL)
            conn = Connection(server, 'put your user here', 'put your pass here', auto_bind=True)
            conn.search('dc=maxcrc,dc=com', '(objectclass=person)')
            allldapentries = conn.entries
            allentrieslist = []
            if allldapentries:
                for x in allldapentries:
                    allentrieslist.append(x)
                print(allentrieslist)
            else:
                print('there are no entries')
    except:
        print('------A connection attempt failed,Server unreachable !-----')


def get_entry_by_UID():
    print('------------Connecting ...Please wait!!-----------')

    try:
        if conn_LDAP():
            print('-----------The connection was successful----------')
            cn = input('Enter The cn Please: ')
            server = Server('put yours here', get_info=ALL)
            conn = Connection(server, 'put your user here', 'put your pass here', auto_bind=True)
            conn.search('dc=maxcrc,dc=com', '(&(objectclass=person)(cn=' + cn + '))',
                        attributes=['sn', 'krbLastPwdChange', 'description', 'telephoneNumber', 'objectclass'])
            ldapentry = conn.entries
            if ldapentry:
                s = str(str(ldapentry[0]).splitlines())
                st0 = s.replace("', '", "-")
                st = st0.replace("'", "-")
                result = re.search('description:(.*)- {4}objectClass', st)
                description = result.group(1).strip()
                result1 = re.search('objectClass:(.*)- {4}sn:', st)
                objectClass = result1.group(1).strip().replace(" ", "")
                result2 = re.search('sn:(.*)- {4}telephone', st)
                sn = result2.group(1).strip()
                result3 = re.search('telephoneNumber:(.*)-', st)
                telephoneNumber = result3.group(1).strip()


            else:
                print('there is no entry with cn : ', cn, ' Try again')
                get_entry_by_UID()
    except:
        print('------A connection attempt failed,Server unreachable !-----')


def check_password():
    try:
        if conn_LDAP():
            print('-----------The connection was successful----------')
            cn = str(input('Enter The cn Please: '))
            server = Server('put yours here', get_info=ALL)
            conn = Connection(server, 'put your user here', 'put your pass here', auto_bind=True)
            result = conn.search('dc=maxcrc,dc=com', '(&(objectclass=person)(cn=' + cn + '))',
                                 attributes=['userPassword'])
            if result:
                ldapentry = conn.entries[0].userPassword
                ldap_value = str(ldapentry)
                ldap_value_bytes = ldap_value[2:-1].encode()
                password_candidate = str(input('Enter The password please: '))

                if hash_sha256(password_candidate) == ldap_value_bytes.decode('ASCII')[8:]:
                    # print(ldap_value_bytes.decode('ASCII'))
                    print('This password is correct and the hash type is "sha256"')
                elif hash_sha1(password_candidate) == ldap_value_bytes.decode('ASCII')[5:]:
                    print('This password is correct and the hash type is "SHA"')
                elif hash_sha512(password_candidate) == ldap_value_bytes.decode('ASCII')[8:].replace(" ", "").replace(
                        r"\n",
                        ""):
                    # print(ldap_value_bytes.decode('ASCII'))
                    print('This password is correct and the hash type is "sha512"')
                elif hash_MD5(password_candidate) == ldap_value_bytes.decode('ASCII')[5:]:
                    # print(ldap_value_bytes.decode('ASCII'))
                    print('This password is correct and the hash type is "MD5"')
                else:
                    print('This password is incorrect... Try again')
                    check_password()
            else:
                print('there is no entry with cn : ', cn, ' or this user dose not have password... Try again')
                check_password()

    except:
        print('------A connection attempt failed,Server unreachable !-----')


def modify_password():
    try:
        if conn_LDAP():
            print('-----------The connection was successful----------')
            cn = str(input('Enter The cn Please: '))
            server = Server('put yours here', get_info=ALL)
            conn = Connection(server, 'put your user here', 'put your pass here', auto_bind=True)
            result = conn.search('dc=maxcrc,dc=com', '(&(objectclass=person)(cn=' + cn + '))',
                                 attributes=['userPassword'])
            if result:
                ldapentry = conn.entries[0].userPassword
                ldap_value = str(ldapentry)
                ldap_value_bytes = ldap_value[2:-1].encode()
                password_candidate = str(input('Enter The old password please: '))

                if hash_sha256(password_candidate) == ldap_value_bytes.decode('ASCII')[8:]:
                    # print(ldap_value_bytes.decode('ASCII'))
                    print('This password is correct and the hash type is "sha256"')
                    password_New = str(input('Enter The New password please: '))
                    hashed_password_New = hash_sha256(password_New)
                    conn.modify('cn=' + cn + 'put your user here',
                                {'userPassword': [(MODIFY_REPLACE, ['' + hashed_password_New + ''])]})
                    print('Modify Response: ', conn.result)
                elif hash_sha1(password_candidate) == ldap_value_bytes.decode('ASCII')[5:]:
                    print('This password is correct and the hash type is "SHA"')
                    password_New = str(input('Enter The New password please: '))
                    hashed_password_New = hash_sha1(password_New)
                    conn.modify('cn=' + cn + 'put your user here',
                                {'userPassword': [(MODIFY_REPLACE, ['' + hashed_password_New + ''])]})
                    print('Modify Response: ', conn.result)
                elif hash_sha512(password_candidate) == ldap_value_bytes.decode('ASCII')[8:].replace(" ", "").replace(
                        r"\n",
                        ""):
                    # print(ldap_value_bytes.decode('ASCII'))
                    print('This password is correct and the hash type is "sha512"')
                    password_New = str(input('Enter The New password please: '))
                    hashed_password_New = hash_sha512(password_New)
                    conn.modify('cn=' + cn + 'put your user here',
                                {'userPassword': [(MODIFY_REPLACE, ['' + hashed_password_New + ''])]})
                    print('Modify Response: ', conn.result)
                elif hash_MD5(password_candidate) == ldap_value_bytes.decode('ASCII')[5:]:
                    # print(ldap_value_bytes.decode('ASCII'))
                    print('This password is correct and the hash type is "MD5"')
                    password_New = str(input('Enter The New password please: '))
                    hashed_password_New = hash_MD5(password_New)
                    conn.modify('cn=' + cn + 'put your user here',
                                {'userPassword': [(MODIFY_REPLACE, ['' + hashed_password_New + ''])]})
                    print('Modify Response: ', conn.result)
                else:
                    print('This password is incorrect... Try again')
                    modify_password()
            else:
                print('there is no entry with cn : ', cn, ' or this user dose not have password... Try again')
                modify_password()
    except:
        print('------A connection attempt failed,Server unreachable !-----')


print('------Welcome to LDAP query python script-------')
print('________________________________________________')

if __name__ == '__main__':
    x = input(
        'Please enter A if you want get all entries or B if you want to get the attributes based on specific cn or\n '
        'C if you want to verify the password based on specific cn or D if you want to modify the password based on\n '
        'specific cn : ')
    if x == 'A' or x == 'a':
        get_all_entries()
    elif x == 'B' or x == 'b':
        get_entry_by_UID()
    elif x == 'c' or x == 'C':
        check_password()
    elif x == 'D' or x == 'd':
        modify_password()
    else:
        print('----Invalid input-----try again please ------Good bey--------')
