# Receives an hex value as RC4 key and decrypts the selected bytes.
#@author jcfg
#@category jcfg
#@keybinding
#@menupath jcfg.RC4_decrypt
#@toolbar 
from Crypto.Cipher import ARC4


def get_bytes(addr, size):
    return bytes(map(lambda b: b & 0xff, getBytes(addr, size)))


def main():
    if not currentSelection():
        popup('No bytes selected!')
        exit(0)

    rc4_key = bytes.fromhex(askString('RC4 Key', 'Key: (e.g. 0432acde)', ''))

    start_addr = currentSelection().getMinAddress()
    end_addr = currentSelection().getMaxAddress().add(1)
    size = end_addr.subtract(start_addr)
    target_bytes = get_bytes(start_addr, size)

    print(f'Decrypting from 0x{start_addr} to 0x{end_addr} ({size} bytes) with key: {rc4_key.hex()}')

    cipher = ARC4.new(rc4_key)
    decrypted = cipher.decrypt(target_bytes)

    currentProgram().getMemory().setBytes(start_addr, decrypted)

if __name__ == '__main__':
    main()
