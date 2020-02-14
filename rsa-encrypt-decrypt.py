import random
import math

def main():
    # The input message to encrypt
    text = get_text()

    # The provided number length of p and q.
    pL = get_porqL('p')
    qL = get_porqL('q')

    keys = get_keys(pL, qL)

    # N: Product of p and q.
    N = get_N(keys['p'], keys['q'])

    print()
    print('Generated Keys:', 'p:', keys['p'], '| q:', keys['q'], '| e:', keys['e'], '| d:', keys['d'], '|')

    print()
    print('Original text:')
    print(text)

    print()
    print('Encrypted Text:')
    encryptedText = encrypt(text, keys['e'], N)
    encryptedText = ' '.join(encryptedText) # String of each letter value separated by space.
    print(encryptedText)

    encryptedText = encryptedText.split()   # List each letter value as element.
    decryptedText = decrypt(encryptedText, keys['d'], N)
    print()
    print('Decrypted Text:')
    print(''.join(decryptedText))


def decrypt(encryptedText, d, N):
    decryptedText = []
    for value in encryptedText:
        value = int(value)
        decryptedValue = pow(value, d, N)
        letter = chr(decryptedValue)
        letter = str(letter)
        decryptedText.append(letter)
    return decryptedText


def encrypt(text, e, N):
    encryptedText= []
    for symbol in text:
        value = ord(symbol)
        encryptedValue = pow(value, e, N)
        encryptedValue = str(encryptedValue)
        encryptedText.append(encryptedValue)
    return encryptedText


def get_N(p, q):
    return p * q


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


def get_porqL(porq):
    while True:
        try:
            print('Provide the number of digits for', porq,'. E.g. 1 for prime numbers 2, 3, 5, 7.')
            answer = int(input('> '))
            # Number length needs to be larger than 0.
            if answer > 0:
                break
            else:
                print('The number need to be larger than 0.')
        except:
            print('Invalid input.')
    return answer


def get_text():
    while True:
        try:
            print('Type in the message that you wish to encrypt.')
            answer = str(input('> '))
            # Incase the message is empty.
            if len(answer) > 2:
                break
            else:
                print('Message needs to be atleast 3 characters in length.')
        except:
            print('Invalid input.')
    return answer


if __name__ == '__main__':
    main()
