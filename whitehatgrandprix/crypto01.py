from pwn import *

r = remote('15.164.159.194', 8006)
ciphertext = str(r.recvuntil('\n')).split(' ')[3:]
ciphertext[-1] = ciphertext[-1].replace('n', '').replace('\\', '').replace("'", '')
print(ciphertext)

chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~`!@#$%^&*()_-+=<,>.?|"
password = [' ' for x in range(64)]

characters = ''
r.recvuntil('choice: ')

for i in chars:
    r.send('1\n')
    r.recvuntil('message: ')
    r.send('{}\n'.format(i*64))
    test = str(r.recvuntil('\n'), 'utf-8').replace('\n', '').split(' ')
    #print(test)
    for j in range(len(test)):
        if len(test[j]) == len(ciphertext[j]):
            if i in "abcdabcdefghijklmnopqrstuvwxyz":
                if test[j][12:14] == ciphertext[j][12:14]:
                    print("Character %s in position %i" % (i, j+1))
                    password[j] = i
                    print(''.join(password))
 
            elif i in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                if test[j][6:8] == ciphertext[j][6:8]:
                    print("Character %s in position %i" % (i, j+1))
                    password[j] = i
                    print(''.join(password))
            elif i in "012345678":
                if test[j][12:14] == ciphertext[j][12:14]:
                    print("Character %s in position %i" % (i, j+1))
                    password[j] = i
                    print(''.join(password))
            else:
                if test[j][0:2] == ciphertext[j][0:2]:
                    print("Character %s in position %i" % (i, j+1))
                    password[j] = i
                    print(''.join(password))
r.interactive()