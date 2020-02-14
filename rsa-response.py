import math
import random

def main():
    # Alice has sent message to bob, with bob's public keys. Only bob can decrypt the message with his private keys.
    # To read the message, without being bob, we need to derive his private keys, from his public keys.

    # received message keys.
    # Given public keys.
    e_bob = 311
    N_bob = 28774274420569
    # Read in the encrypted message in file, as a string.
    ctext = readF('gr05.txt')
    factors = factorize(N_bob)
    p_bob = factors[0]
    q_bob = factors[1]
    phi_bob = get_phi(p_bob, q_bob)
    N_bob = get_N(p_bob, q_bob)
    # Generate decryption key, d.
    d_bob = modinv(e_bob, phi_bob)
    # Decrypt the message
    dtext = decrypt(ctext, d_bob, N_bob)
    translatedText = get_symbols(dtext)
    # received message program output
    rec_output(ctext, e_bob, N_bob, p_bob, q_bob, phi_bob, d_bob, translatedText)


    # To respond to Alice's message
    # Response message keys.
    # In the RSA scheme a message is sent encrypted with the recievers public keys.
    # This lab assignment is flawed, it wants us to send the message encrypted with our own public keys, thus the receiver can't decrypt the message.
    # We do not know Alice's public keys, nor would it be suitable to generate keys for her, since it would defeat the purpose of encryption.
    pL = len(str(p_bob))
    qL = len(str(q_bob))
    keys = get_keys(pL, qL)
    p = keys['p']
    q = keys['q']
    e = keys['e']   # Our own public keys for encryption?
    d = keys['d']
    N = p * q # Our own public keys for encryption?
    phi = (p - 1) * (q - 1) # Not needed
    text = 'Ok, message received'   # Original response.
    # Translate message into decimals.
    decimalText = get_decimalText(text) # Convert the text into decimals, as one string.
    # Encrypt the message.
    ctext = encrypt(decimalText, e, N) # Encrypted text, in blocks of 3 letters each.

    # ---------- Decryption of the encrypted message to make sure it works properly. ----------
    dtext = decrypt(ctext, d, N)
    translatedText = get_symbols(dtext)
    # Response message program output.
    resp_output(text, p, q, e, d, N, phi, ctext, dtext, translatedText)


def resp_output(text, p, q, e, d, N, phi, ctext, dtext, translatedText):
    # Program output
    print('-'*10 +  'Response message' + '-'*10)
    print('Original message:')
    print(text)
    print()
    print('Created public keys:')
    print('e:', e, '| n:', N)
    print()
    print('Created private keys:')
    print('p:', p, ' | q:', q, '| phi:', phi, '| d:', d)
    print()
    print('Encrypted text:')
    print(ctext)
    print()
    print('Decrypted text:')
    print(' '.join(map(str, dtext)))
    print()
    print('Translation:')
    print(translatedText)


def encrypt(decimalText, e, N):
    ctext = []
    # Encrypts the text string in decimals in blocks of 3 letters each block. Each letter is 3 decimals (according to ord()).
    for block in decimalText:    # 3 letters each block => 3*3=9.
        cBlock = pow(int(block), e, N)   # RSA encryption.
        ctext.append(str(cBlock))
    return ' '.join(ctext)


def get_decimalText(text):
    # input is a string, output list of each block of 3 characters as 3 decimals each => 9 numbers each block.
    decimalText = ''
    count = 0
    for symbol in text:
        decimalSymbol = str(ord(symbol))
        if len(decimalSymbol) < 3:
            decimalSymbol = decimalSymbol.zfill(3)
        decimalText += decimalSymbol
        count += 1
        if count == 3:
            decimalText += ' ' # Add a space for every block of 3 characters in decimals.
            count = 0
    return decimalText.split()


def rec_output(ctext, e, N, p, q, phi, d, translatedText):
    # Program output
    print('-'*10 +  'received message' + '-'*10)
    print('Original message:')
    print(ctext)
    print()
    print('Given public keys:')
    print('e:', e, '| n:', N)
    print()
    print('Derived private keys:')
    print('p:', p, ' | q:', q, '| phi:', phi, '| d:', d)
    print()
    print('Decrypted text:')
    print(translatedText)
    print()
    print('Manually Added spaces:')
    print('Our analysis suggests that related-key differential attacks against')
    print()


def get_keys(pL, qL):
    # Generate p and q.
    p = get_prime(pL)
    q = get_prime(qL)
    phi = (p - 1) * (q - 1)
    # Generate e that is coprime with phi.
    while True:
        e = random.randint(1, 100000)
        if math.gcd(e, phi) == 1:
            break
    # Generate d.
    d = modinv(e, phi)
    keys = {'p': p, 'q': q, 'e': e, 'd': d}
    return keys


def miller_rabin(n, k):
    # Modified for python3 and error fix from https://gist.github.com/Ayrx/5884790
    # Implementation uses the Miller-Rabin Primality Test
    # The optimal number of rounds for this test is 40
    # See http://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
    # for justification
    # If number is even, it's a composite number
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def get_prime(n):
    # Returns a prime number of length n.
    # The number range e.g. for 1 its 1 and 9.
    range_start = 10 ** (n - 1)
    range_end = (10 ** n) - 1
    while True:
        # The only even prime number is 2, thus only interested in odd numbers.
        # 2*(k//2)+1, will always derive a odd number from a given number k.
        candidate = (2 * (random.randrange(range_start, range_end)//2)) + 1
        # Miller-Rabin Primality Test with 40 rounds of test, see the function for link as to why 40 iterations.
        # If the generated number is not prime, new iteration, new number, new test...
        if miller_rabin(candidate, 40) == True:
            break
    return candidate


def get_symbols(dtext):
    # Convert list elements to symbols.
    text = []   # Each element a word.
    sWord = ''  # New word decimals are now symbols
    for block in dtext:
        for i in range(0, len(str(block)), 3):   # Every third decimal in the block range.
            decimalLetter = str(block)[i] + str(block)[i + 1] + str(block)[i + 2]  # The iteration + 2 right neightbors.
            symbol = chr(int(decimalLetter))
            sWord += symbol
        text.append(sWord)
        sWord = ''
    return ''.join(text)


def decrypt(ctext, d, N):
    # RSA decryption.
    dtext = []
    ctext = ctext.split() # List, each element each encrypted block.
    for block in ctext:
        dValue = pow(int(block), d, N)
        if len(str(dValue)) != 9:
            dValue = str(dValue).zfill(9)   # Each block is 9 length, each ASCII character is 3 length.
        # if len(str(dValue)) % 2 == 0: # If the length of decrypted block is even, there is a missing leading 0, removed because of int(). Unicode letters are represented by 3 decimals.
        #     dValue = str(dValue).zfill(len(str(dValue)) + 1) # Adds a zero to the start.
        dtext.append(dValue) # RSA Decryption
    return dtext # List


def get_N(p, q):
    return p * q


def get_phi(p, q):
    return (p - 1) * (q - 1)


def xgcd(a, b):
    # https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


def modinv(a, b):
    # https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    """return x such that (x * a) % b == 1"""
    g, x, _ = xgcd(a, b)
    if g != 1:
        raise Exception('gcd(a, b) != 1')
    return x % b


def readF(filename):
    # Reads in textfile, content as string.
    with open(filename, 'r') as f:
        content = f.readlines()
    return ''.join(content)


def factorize(n):
    # Fermat's prime number factorization.
    # Returns a - factor 1, b - factor 2, x - step.
    step = 0
    while True:
        step += 1
        x = abs(int(n ** 0.5)) + step
        if (x ** 2 - n) ** 0.5 - int((x ** 2 - n) ** 0.5) == 0:
            a = x + (x ** 2 - n) ** 0.5
            b = x - (x ** 2 - n) ** 0.5
            break
    return [int(a), int(b)]


def get_x(n, step):
    return abs(int(n ** 0.5)) + step


def checkSquare(x):
    # square root of x.
    sqr = math.sqrt(x)
    # If square root is an integer
    return ((sqr - math.floor(sqr)) == 0)



if __name__ == '__main__':
    main()
