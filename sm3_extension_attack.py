from gmssl import sm3, func
def extension_message(msg):
    len1 = len(msg)
    reserve1 = len1 % 64
    msg.append(0x80)
    reserve1 = reserve1 + 1
    range_end = 56
    if reserve1 > range_end:
        range_end = range_end + 64  
    for i in range(reserve1, range_end):
        msg.append(0x00)
    
    bit_length = (len1) * 8
    bit_length_str = [bit_length % 0x100]
    for i in range(7):
        bit_length = int(bit_length / 0x100)
        bit_length_str.append(bit_length % 0x100)
    for i in range(8):
        msg.append(bit_length_str[7-i])
    return msg
        

def extension_attack():
    message=b"abcde"
    msg_add=b"qwert"

    #正常对message+补位+msg_add进行散列
    message1=extension_message(func.bytes_to_list(message))
    message_add=message1+func.bytes_to_list(msg_add)
    hash_value1=sm3.sm3_hash(message_add)
    '''
    先对message进行散列得到密文，然后将密文作为压缩函数的初始值对
    message+补位+msg_add的第二个分组进行散列，所以只需要知
    道message的散列值和长度，不需要知道message具体是啥，就能得到message+补位+msg_add
    的散列值，实现了长度拓展攻击。
    '''
    y=sm3.sm3_hash(func.bytes_to_list(message))
    IV=[]
    for i in range(0,8):
        IV.append(int(y[i*8:(i+1)*8],16))
    message2=extension_message(message_add)
    y2=sm3.sm3_cf(IV,message2[64:128])
    hash_value2= ""
    for i in y2:
        hash_value2 = '%s%08x' % (hash_value2, i)
    
    if hash_value1==hash_value2:
        print("attack is ok!")
        print ("hash_value is:",hash_value1)
if __name__ == "__main__":
    extension_attack()
