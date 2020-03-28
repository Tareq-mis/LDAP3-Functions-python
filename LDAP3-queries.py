from ldap3 import Server, ALL, Connection
from passlib.hash import sha256_crypt
import os

def conn_LDAP():
    server = Server('193.6.5.58')
    conn = Connection(server)
    return conn.bind()


def get_all_entries():
    print('------------Connecting ...Please wait!!-----------')
    try:
        if conn_LDAP():
            print('-----------The connection was successful----------')
            server = Server('193.6.5.58', get_info=ALL)
            conn = Connection(server, 'ou=csop_HU,ou=ev2020,ou=meinfo,dc=maxcrc,dc=com', 'H578', auto_bind=True)
            conn.search('dc=maxcrc,dc=com', '(objectclass=person)')
            allldapentries = conn.entries
            allentrieslist = []
            for x in allldapentries:
                allentrieslist.append(x)
            print(allentrieslist)
            #print(type(allentrieslist))
    except:
        print('------A connection attempt failed,Server unreachable !-----')


def get_entry_by_UID():
    print('------------Connecting ...Please wait!!-----------')

    try:
        if conn_LDAP():
            print('-----------The connection was successful----------')
            cn = input('Enter The cn Please: ')
            server = Server('193.6.5.58', get_info=ALL)
            conn = Connection(server, 'ou=csop_HU,ou=ev2020,ou=meinfo,dc=maxcrc,dc=com', 'H578', auto_bind=True)
            conn.search('dc=maxcrc,dc=com', '(&(objectclass=person)(cn=' + cn + '))',
                        attributes=['sn', 'description', 'telephoneNumber', 'objectclass'])
            ldapentry = conn.entries
            if ldapentry:
                print(ldapentry)
            else:
                print('there is no entry with cn : ', cn)
    except:
        print('------A connection attempt failed,Server unreachable !-----')

def check_password(tagged_digest_salt, password):
    try:
        if conn_LDAP():
            print('-----------The connection was successful----------')
            cn = input('Enter The cn Please: ')
            server = Server('193.6.5.58', get_info=ALL)
            conn = Connection(server, 'ou=csop_HU,ou=ev2020,ou=meinfo,dc=maxcrc,dc=com', 'H578', auto_bind=True)
            conn.search('dc=maxcrc,dc=com', '(&(objectclass=person)(cn=' + cn + '))',
                        attributes=['userPassword'])
            ldapentry = conn.entries[0]
            if ldapentry:
                print(ldapentry)
            else:
                print('there is no entry with cn : ', cn)
    except:
        print('------A connection attempt failed,Server unreachable !-----')
    """
    Checks the OpenLDAP tagged digest against the given password
    """
    #if sha256_crypt.verify(password_candidate, password):

print('------Welcome to LDAP query python script-------')
x = input('Please enter A if you want get all entries or B if you want to get the attributes based on specific cn: ')
if x == 'A' or x == 'a':
    get_all_entries()

elif x == 'B' or x == 'b':
    get_entry_by_UID()
elif x == 'c' or x == 'C':
    check_password('fEqNCco3Yq9h5ZUglD3CZJT4lBs=', '123456')
else:
    print('----Invalid input-----try again please ------Good bey--------')
